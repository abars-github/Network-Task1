/*
 * Inline TCP-payload protection between two Linux devices (prototype, C version).
 *
 *   PC1 -> Device1 ==(TCP, same IP/TCP headers, payload = AES-GCM ct||tag)==> Device2 -> PC2
 *
 * Handshake : X25519 Diffie-Hellman on a separate device<->device TCP control connection,
 *             authenticated with a pre-shared key (HMAC-SHA256), keys via HKDF-SHA256.
 * Data plane: iptables NFQUEUE hands marked TCP/IPv4 packets to this program (mark 1 = from
 *             the local side -> encrypt, mark 2 = from the peer -> decrypt).  Only the TCP
 *             payload is replaced by ciphertext||16-byte tag.  IP/TCP headers are kept, the
 *             IP total length and the IP/TCP checksums are recomputed.  No UDP, no extra header.
 * Nonce     : 96 bit = 4-byte per-direction salt || 64-bit counter.  The sender increments the
 *             counter for EVERY encrypted packet (retransmissions too), so a nonce is never
 *             reused under a key.  Nothing extra is on the wire, so the receiver recovers the
 *             counter by trial decryption in a window around the next expected value (the GCM
 *             tag tells which one is right) and rejects replays with a bitmap.
 *
 * Build: make            (needs libssl-dev, libnetfilter-queue-dev)
 *        make selftest   (needs only libssl-dev; no root, no network setup)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#ifndef NO_NFQ
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

#define TAGLEN   16
#define AHEAD    256
#define BACK     64
#define MAX_CTR  (1ULL << 48)
#define MARK_ENC 1
#define MARK_DEC 2
#define KDF_INFO "inline-aesgcm-v1"
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0   /* macOS: SIGPIPE is ignored in main()/selftest instead */
#endif

/* ------------------------------------------------------------ session state */
typedef struct { uint8_t key[32]; uint8_t salt[4]; uint64_t n; } TxDir;
typedef struct { uint8_t key[32]; uint8_t salt[4]; uint64_t next; uint64_t mask; } RxDir;
typedef struct { TxDir tx; RxDir rx; } Session;

static Session g_sess;
static int g_have;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct { char peer[64]; char bind[64]; int ctl_port; int queue; } Cfg;
static struct { Cfg cfg; uint8_t psk[4096]; size_t pl; } g_ctx;

static void install(const Session *s)
{
    pthread_mutex_lock(&g_lock);
    g_sess = *s;
    g_have = 1;
    pthread_mutex_unlock(&g_lock);
}

/* -------------------------------------------------------------------- AES-GCM */
static void make_iv(uint8_t iv[12], const uint8_t salt[4], uint64_t c)
{
    memcpy(iv, salt, 4);
    for (int i = 0; i < 8; i++) iv[4 + i] = (uint8_t)(c >> (56 - 8 * i));
}

/* out must hold ptl + 16 bytes: ciphertext followed by the tag */
static int gcm_seal(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, int aadl,
                    const uint8_t *pt, int ptl, uint8_t *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ok = 0;
    if (!c) return 0;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(c, NULL, &l, aad, aadl) == 1 &&
        EVP_EncryptUpdate(c, out, &l, pt, ptl) == 1 && l == ptl &&
        EVP_EncryptFinal_ex(c, out + ptl, &l) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAGLEN, out + ptl) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

/* blob = ciphertext||tag, bl > 16; writes bl-16 plaintext bytes; 1 only if the tag verifies */
static int gcm_open(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, int aadl,
                    const uint8_t *blob, int bl, uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ok = 0, ptl = bl - TAGLEN;
    if (!c) return 0;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(c, NULL, &l, aad, aadl) == 1 &&
        EVP_DecryptUpdate(c, pt, &l, blob, ptl) == 1 && l == ptl &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAGLEN, (void *)(blob + ptl)) == 1 &&
        EVP_DecryptFinal_ex(c, pt + ptl, &l) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static int tx_seal(TxDir *t, const uint8_t *aad, int aadl, const uint8_t *pt, int ptl, uint8_t *out)
{
    uint8_t iv[12];
    if (t->n >= MAX_CTR) return 0;             /* nonce space exhausted: re-handshake needed */
    make_iv(iv, t->salt, t->n++);              /* counter consumed even if sealing fails */
    return gcm_seal(t->key, iv, aad, aadl, pt, ptl, out);
}

static int rx_try(RxDir *r, uint64_t c, const uint8_t *aad, int aadl,
                  const uint8_t *blob, int bl, uint8_t *pt)
{
    uint8_t iv[12];
    make_iv(iv, r->salt, c);
    if (!gcm_open(r->key, iv, aad, aadl, blob, bl, pt)) return 0;
    if (c >= r->next) {                        /* advance window */
        uint64_t nn = c + 1, d = nn - r->next;
        r->mask = d >= 64 ? 0 : r->mask << d;
        r->mask |= 1;                          /* bit i = counter (next-1-i) already seen */
        r->next = nn;
    } else {
        r->mask |= 1ULL << (r->next - 1 - c);
    }
    return 1;
}

static int rx_open(RxDir *r, const uint8_t *aad, int aadl, const uint8_t *blob, int bl, uint8_t *pt)
{
    if (bl <= TAGLEN) return 0;
    for (uint64_t k = 0; k <= AHEAD; k++)      /* expected counter, then looking ahead (loss) */
        if (rx_try(r, r->next + k, aad, aadl, blob, bl, pt)) return 1;
    for (uint64_t k = 1; k <= BACK && k <= r->next; k++) {   /* reordering; skip replays */
        if (r->mask & (1ULL << (k - 1))) continue;
        if (rx_try(r, r->next - k, aad, aadl, blob, bl, pt)) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------- key schedule */
static void mac(const uint8_t *key, size_t kl, const uint8_t *msg, size_t ml, uint8_t out[32])
{
    unsigned int ol = 32;
    HMAC(EVP_sha256(), key, (int)kl, msg, ml, out, &ol);
}

/* HKDF-SHA256 (RFC 5869), salt = ri||rr, 72 bytes of output */
static void derive_keys(const uint8_t secret[32], const uint8_t ri[16], const uint8_t rr[16],
                        int initiator, Session *s)
{
    uint8_t salt[32], prk[32], t[32], buf[32 + 16 + 1], km[96];
    size_t il = strlen(KDF_INFO);
    memcpy(salt, ri, 16); memcpy(salt + 16, rr, 16);
    mac(salt, 32, secret, 32, prk);
    for (int i = 0; i < 3; i++) {
        size_t n = 0;
        if (i) { memcpy(buf, t, 32); n = 32; }
        memcpy(buf + n, KDF_INFO, il); n += il;
        buf[n++] = (uint8_t)(i + 1);
        mac(prk, 32, buf, n, t);
        memcpy(km + 32 * i, t, 32);
    }
    const uint8_t *k_i2r = km, *k_r2i = km + 32, *s_i2r = km + 64, *s_r2i = km + 68;
    memset(s, 0, sizeof *s);
    memcpy(s->tx.key, initiator ? k_i2r : k_r2i, 32);
    memcpy(s->tx.salt, initiator ? s_i2r : s_r2i, 4);
    memcpy(s->rx.key, initiator ? k_r2i : k_i2r, 32);
    memcpy(s->rx.salt, initiator ? s_r2i : s_i2r, 4);
    OPENSSL_cleanse(km, sizeof km); OPENSSL_cleanse(prk, sizeof prk); OPENSSL_cleanse(t, sizeof t);
}

/* -------------------------------------------------------------------- X25519 */
static int gen_x25519(EVP_PKEY **sk, uint8_t pub[32])
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t l = 32;
    int ok = 0;
    if (!c) return 0;
    *sk = NULL;
    if (EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_keygen(c, sk) == 1 &&
        EVP_PKEY_get_raw_public_key(*sk, pub, &l) == 1 && l == 32) ok = 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static int dh(EVP_PKEY *sk, const uint8_t peer[32], uint8_t secret[32])
{
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(sk, NULL);
    size_t l = 32;
    int ok = 0;
    if (p && c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, p) == 1 &&
        EVP_PKEY_derive(c, secret, &l) == 1 && l == 32) {
        uint8_t z = 0;                          /* reject all-zero output (low-order point) */
        for (int i = 0; i < 32; i++) z |= secret[i];
        ok = z != 0;
    }
    EVP_PKEY_free(p); EVP_PKEY_CTX_free(c);
    return ok;
}

/* ----------------------------------------------------------------- handshake */
static int recv_exact(int fd, uint8_t *b, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, b + got, n - got, 0);
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}

static int send_all(int fd, const uint8_t *b, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, b + sent, n - sent, MSG_NOSIGNAL);
        if (r <= 0) return 0;
        sent += (size_t)r;
    }
    return 1;
}

static void set_timeouts(int fd)
{
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

/* I->R: pub(32) ri(16) HMAC(psk,"I"||pub||ri)
 * R->I: pub(32) rr(16) HMAC(psk,"R"||rpub||rr||ipub||ri) */
static int initiate(const Cfg *a, const uint8_t *psk, size_t pl, Session *out)
{
    EVP_PKEY *sk = NULL;
    uint8_t pub[32], ri[16], msg[80], rsp[80], buf[97], m[32], secret[32];
    int fd = -1, rc = -1;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)a->ctl_port) };

    if (inet_pton(AF_INET, a->peer, &sa.sin_addr) != 1) goto done;
    if (!gen_x25519(&sk, pub) || RAND_bytes(ri, 16) != 1) goto done;
    buf[0] = 'I'; memcpy(buf + 1, pub, 32); memcpy(buf + 33, ri, 16);
    mac(psk, pl, buf, 49, m);
    memcpy(msg, pub, 32); memcpy(msg + 32, ri, 16); memcpy(msg + 48, m, 32);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) goto done;
    set_timeouts(fd);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) goto done;
    if (!send_all(fd, msg, 80) || !recv_exact(fd, rsp, 80)) goto done;

    buf[0] = 'R'; memcpy(buf + 1, rsp, 32); memcpy(buf + 33, rsp + 32, 16);
    memcpy(buf + 49, pub, 32); memcpy(buf + 81, ri, 16);
    mac(psk, pl, buf, 97, m);
    if (CRYPTO_memcmp(m, rsp + 48, 32) != 0) { fprintf(stderr, "peer authentication failed\n"); goto done; }
    if (!dh(sk, rsp, secret)) goto done;
    derive_keys(secret, ri, rsp + 32, 1, out);
    rc = 0;
done:
    if (fd >= 0) close(fd);
    EVP_PKEY_free(sk);
    OPENSSL_cleanse(secret, sizeof secret);
    return rc;
}

static int respond(int fd, const uint8_t *psk, size_t pl)
{
    EVP_PKEY *sk = NULL;
    uint8_t in[80], pub[32], rr[16], rsp[80], buf[97], m[32], secret[32];
    Session s;
    int rc = -1;

    if (!recv_exact(fd, in, 80)) goto done;
    buf[0] = 'I'; memcpy(buf + 1, in, 32); memcpy(buf + 33, in + 32, 16);
    mac(psk, pl, buf, 49, m);
    if (CRYPTO_memcmp(m, in + 48, 32) != 0) { fprintf(stderr, "handshake rejected: bad authentication\n"); goto done; }
    if (!gen_x25519(&sk, pub) || RAND_bytes(rr, 16) != 1 || !dh(sk, in, secret)) goto done;
    derive_keys(secret, in + 32, rr, 0, &s);
    install(&s);                                /* ready before the initiator can send data */
    buf[0] = 'R'; memcpy(buf + 1, pub, 32); memcpy(buf + 33, rr, 16);
    memcpy(buf + 49, in, 32); memcpy(buf + 81, in + 32, 16);
    mac(psk, pl, buf, 97, m);
    memcpy(rsp, pub, 32); memcpy(rsp + 32, rr, 16); memcpy(rsp + 48, m, 32);
    if (!send_all(fd, rsp, 80)) goto done;
    rc = 0;
done:
    EVP_PKEY_free(sk);
    OPENSSL_cleanse(secret, sizeof secret);
    return rc;
}

static void *serve_thread(void *arg)
{
    (void)arg;
    int srv = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)g_ctx.cfg.ctl_port) };
    if (srv < 0 || inet_pton(AF_INET, g_ctx.cfg.bind, &sa.sin_addr) != 1) { perror("control socket"); exit(1); }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(srv, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(srv, 4) != 0) { perror("control bind"); exit(1); }
    for (;;) {
        struct sockaddr_in pa; socklen_t pl = sizeof pa;
        int fd = accept(srv, (struct sockaddr *)&pa, &pl);
        if (fd < 0) continue;
        set_timeouts(fd);
        if (respond(fd, g_ctx.psk, g_ctx.pl) == 0) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pa.sin_addr, ip, sizeof ip);
            printf("session established with %s\n", ip); fflush(stdout);
        }
        close(fd);
    }
    return NULL;
}

static void *initiate_thread(void *arg)
{
    (void)arg;
    for (;;) {
        Session s;
        if (initiate(&g_ctx.cfg, g_ctx.psk, g_ctx.pl, &s) == 0) {
            install(&s);
            printf("session established\n"); fflush(stdout);
            return NULL;
        }
        fprintf(stderr, "handshake failed, retrying\n");
        sleep(2);
    }
}

/* ---------------------------------------------------------------- data plane */
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint32_t sum16(const uint8_t *d, size_t n, uint32_t s)
{
    size_t i;
    for (i = 0; i + 1 < n; i += 2) s += (uint32_t)((d[i] << 8) | d[i + 1]);
    if (n & 1) s += (uint32_t)(d[n - 1] << 8);
    return s;
}
static uint16_t fold(uint32_t s)
{
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)(~s & 0xFFFF);
}

static void pseudo(uint8_t ph[12], const uint8_t *p, int tcplen)
{
    memcpy(ph, p + 12, 8);
    ph[8] = 0; ph[9] = 6; ph[10] = (uint8_t)(tcplen >> 8); ph[11] = (uint8_t)tcplen;
}

/* set IP total length, IP header checksum and TCP checksum in place */
static void finalize(uint8_t *p, int total, int ihl)
{
    uint8_t ph[12];
    uint16_t c;
    p[2] = (uint8_t)(total >> 8); p[3] = (uint8_t)total;
    p[10] = p[11] = 0;
    c = fold(sum16(p, (size_t)ihl, 0));
    p[10] = (uint8_t)(c >> 8); p[11] = (uint8_t)c;
    p[ihl + 16] = p[ihl + 17] = 0;
    pseudo(ph, p, total - ihl);
    c = fold(sum16(p + ihl, (size_t)(total - ihl), sum16(ph, 12, 0)));
    p[ihl + 16] = (uint8_t)(c >> 8); p[ihl + 17] = (uint8_t)c;
}

static int checksums_ok(const uint8_t *p, int total)
{
    uint8_t ph[12];
    int ihl = (p[0] & 15) * 4;
    if (fold(sum16(p, (size_t)ihl, 0)) != 0) return 0;
    pseudo(ph, p, total - ihl);
    return fold(sum16(p + ihl, (size_t)(total - ihl), sum16(ph, 12, 0))) == 0;
}

/* Rewrites one packet into out (>= len + 16 bytes). Returns new length, or -1 to drop. */
static int process(const uint8_t *raw, int len, uint32_t mark, int have, Session *s, uint8_t *out)
{
    if (len < 40 || (raw[0] >> 4) != 4 || raw[9] != 6) return -1;
    int ihl = (raw[0] & 15) * 4, total = be16(raw + 2);
    if (ihl < 20 || (be16(raw + 6) & 0x3FFF) || total > len || total < ihl + 20) return -1; /* fragments */
    int doff = (raw[ihl + 12] >> 4) * 4;
    if (doff < 20 || ihl + doff > total) return -1;
    int pl = total - ihl - doff;
    if (pl == 0) { memcpy(out, raw, (size_t)len); return len; }  /* SYN/ACK/FIN: never protected */
    if (!have) return -1;                                         /* fail closed before handshake */

    uint8_t aad[20];                       /* src/dst IP, ports, seq, ack are authenticated */
    memcpy(aad, raw + 12, 8);
    memcpy(aad + 8, raw + ihl, 12);
    memcpy(out, raw, (size_t)(ihl + doff));
    int newtotal;
    if (mark == MARK_ENC) {
        if (!tx_seal(&s->tx, aad, 20, raw + ihl + doff, pl, out + ihl + doff)) return -1;
        newtotal = total + TAGLEN;
    } else if (mark == MARK_DEC) {
        if (!rx_open(&s->rx, aad, 20, raw + ihl + doff, pl, out + ihl + doff)) return -1;
        newtotal = total - TAGLEN;
    } else return -1;
    finalize(out, newtotal, ihl);
    return newtotal;
}

#ifndef NO_NFQ
static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *d)
{
    static uint8_t out[70000];
    (void)nfmsg; (void)d;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *data = NULL;
    int len = nfq_get_payload(nfa, &data), n = -1;
    if (len > 0 && len <= 65535) {
        pthread_mutex_lock(&g_lock);
        n = process(data, len, nfq_get_nfmark(nfa), g_have, &g_sess, out);
        pthread_mutex_unlock(&g_lock);
    }
    if (n < 0) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)n, out);
}

static void run_queue(int qnum)
{
    static uint8_t buf[70000];
    struct nfq_handle *h = nfq_open();
    if (!h) { fprintf(stderr, "nfq_open failed (root? libnetfilter_queue?)\n"); exit(1); }
    struct nfq_q_handle *qh = nfq_create_queue(h, (uint16_t)qnum, &nfq_cb, NULL);
    if (!qh) { fprintf(stderr, "cannot bind queue %d (already in use?)\n", qnum); exit(1); }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xFFFF);
    nfq_set_queue_maxlen(qh, 4096);
    int fd = nfq_fd(h), one = 1;
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof one);
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r >= 0) nfq_handle_packet(h, (char *)buf, (int)r);
        else if (errno != ENOBUFS && errno != EINTR) { perror("recv"); break; }
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
}
#endif

/* ------------------------------------------------------------------ self-test */
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "SELFTEST FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

static int build(const uint8_t src[4], const uint8_t dst[4], uint16_t sp, uint16_t dp,
                 uint32_t seq, uint32_t ack, const uint8_t *pl, int plen, uint8_t *p)
{
    memset(p, 0, 40);
    p[0] = 0x45; p[4] = 0; p[5] = 1; p[6] = 0x40; p[8] = 64; p[9] = 6;
    memcpy(p + 12, src, 4); memcpy(p + 16, dst, 4);
    p[20] = (uint8_t)(sp >> 8); p[21] = (uint8_t)sp; p[22] = (uint8_t)(dp >> 8); p[23] = (uint8_t)dp;
    for (int i = 0; i < 4; i++) { p[24 + i] = (uint8_t)(seq >> (24 - 8 * i)); p[28 + i] = (uint8_t)(ack >> (24 - 8 * i)); }
    p[32] = 5 << 4; p[33] = 0x18; p[34] = p[35] = 0xFF;
    memcpy(p + 40, pl, (size_t)plen);
    finalize(p, 40 + plen, 20);
    return 40 + plen;
}

static void selftest(void)
{
    signal(SIGPIPE, SIG_IGN);
    uint8_t ri[16], rr[16], secret[32];
    Session A, B;
    RAND_bytes(ri, 16); RAND_bytes(rr, 16); RAND_bytes(secret, 32);
    derive_keys(secret, ri, rr, 1, &A);
    derive_keys(secret, ri, rr, 0, &B);
    CHECK(!memcmp(A.tx.key, B.rx.key, 32) && !memcmp(A.rx.key, B.tx.key, 32));
    CHECK(memcmp(A.tx.key, A.rx.key, 32) != 0);

    const uint8_t P1[4] = {10, 0, 1, 2}, P2[4] = {10, 0, 2, 2};
    static uint8_t pk[5][2000], enc[5][2000], dec[2000], tmp[2000], pay[2000];
    int pl[5], el[5], n;
    for (int i = 0; i < 5; i++) {
        int plen = 100 + 37 * i;
        RAND_bytes(pay, plen);
        pl[i] = build(P1, P2, 40000, 8080, 1000 + i, 5, pay, plen, pk[i]);
        CHECK(checksums_ok(pk[i], pl[i]));
    }
    for (int i = 0; i < 5; i++) {
        el[i] = process(pk[i], pl[i], MARK_ENC, 1, &A, enc[i]);
        CHECK(el[i] == pl[i] + TAGLEN && checksums_ok(enc[i], el[i]));
        CHECK(!memcmp(enc[i] + 12, pk[i] + 12, 20));                        /* headers preserved */
        CHECK(memcmp(enc[i] + 40, pk[i] + 40, (size_t)(pl[i] - 40)) != 0);  /* payload encrypted */
    }
    for (int i = 0; i < 5; i++) {                                           /* exact restore */
        n = process(enc[i], el[i], MARK_DEC, 1, &B, dec);
        CHECK(n == pl[i] && !memcmp(dec, pk[i], (size_t)n) && checksums_ok(dec, n));
    }
    CHECK(process(enc[0], el[0], MARK_DEC, 1, &B, dec) < 0);                /* replay rejected */

    static uint8_t more[4][2000]; int ml[4];
    memset(pay, 'x', 50);
    for (int i = 0; i < 4; i++) {
        n = build(P1, P2, 40000, 8080, 2000 + i, 5, pay, 50, tmp);
        ml[i] = process(tmp, n, MARK_ENC, 1, &A, more[i]);
        CHECK(ml[i] > 0);
    }
    CHECK(process(more[3], ml[3], MARK_DEC, 1, &B, dec) > 0);               /* loss tolerated */
    CHECK(process(more[1], ml[1], MARK_DEC, 1, &B, dec) > 0);               /* reordering tolerated */
    CHECK(process(more[1], ml[1], MARK_DEC, 1, &B, dec) < 0);               /* ...but only once */
    memcpy(tmp, more[2], (size_t)ml[2]); tmp[ml[2] - 1] ^= 1;
    CHECK(process(tmp, ml[2], MARK_DEC, 1, &B, dec) < 0);                   /* bad tag */
    memcpy(tmp, more[2], (size_t)ml[2]); tmp[44] ^= 1;
    CHECK(process(tmp, ml[2], MARK_DEC, 1, &B, dec) < 0);                   /* tampered ciphertext */
    memcpy(tmp, more[2], (size_t)ml[2]); tmp[25] ^= 1;
    CHECK(process(tmp, ml[2], MARK_DEC, 1, &B, dec) < 0);                   /* seq number is in AAD */
    CHECK(process(more[2], ml[2], MARK_DEC, 1, &B, dec) > 0);               /* genuine still OK */

    n = build(P2, P1, 8080, 40000, 7, 1100, pay, 50, tmp);                  /* reverse direction */
    int rl = process(tmp, n, MARK_ENC, 1, &B, enc[0]);
    CHECK(rl > 0 && process(enc[0], rl, MARK_DEC, 1, &A, dec) == n && !memcmp(dec, tmp, (size_t)n));

    n = build(P1, P2, 40000, 8080, 1, 2, pay, 0, tmp);                      /* empty segment */
    CHECK(process(tmp, n, MARK_ENC, 1, &A, dec) == n && !memcmp(dec, tmp, (size_t)n));
    CHECK(process(pk[0], pl[0], MARK_ENC, 0, &A, dec) < 0);                 /* no session -> drop */

    /* unique nonces: counter 0..N-1 never repeats, stops at 2^48 */
    A.tx.n = MAX_CTR - 1;
    CHECK(process(pk[0], pl[0], MARK_ENC, 1, &A, dec) > 0);
    CHECK(process(pk[0], pl[0], MARK_ENC, 1, &A, dec) < 0);

    /* real X25519 handshake over loopback, then wrong-PSK rejection */
    memset(&g_ctx, 0, sizeof g_ctx);
    strcpy(g_ctx.cfg.bind, "127.0.0.1"); strcpy(g_ctx.cfg.peer, "127.0.0.1");
    g_ctx.cfg.ctl_port = 19000 + (int)(getpid() % 1000);
    memcpy(g_ctx.psk, "test-psk", 8); g_ctx.pl = 8;
    pthread_t th; pthread_create(&th, NULL, serve_thread, NULL);
    Session HI; int ok = -1;
    for (int i = 0; i < 20 && ok != 0; i++) { usleep(100000); ok = initiate(&g_ctx.cfg, g_ctx.psk, g_ctx.pl, &HI); }
    CHECK(ok == 0);
    usleep(100000);
    pthread_mutex_lock(&g_lock);
    CHECK(g_have && !memcmp(g_sess.rx.key, HI.tx.key, 32) && !memcmp(g_sess.tx.key, HI.rx.key, 32));
    CHECK(!memcmp(g_sess.rx.salt, HI.tx.salt, 4) && !memcmp(g_sess.tx.salt, HI.rx.salt, 4));
    pthread_mutex_unlock(&g_lock);
    Session bad;
    CHECK(initiate(&g_ctx.cfg, (const uint8_t *)"wrong-psk", 9, &bad) != 0);
    puts("self-test OK (packet rewrite, checksums, replay/loss/reorder, tamper, nonce limit, X25519 handshake)");
}

/* ----------------------------------------------------------------------- main */
static void usage(void)
{
    fprintf(stderr,
        "usage: secure_link --role initiator|responder --psk-file F [--peer IP] [--bind IP]\n"
        "                   [--ctl-port 9000] [--queue 0]\n       secure_link --selftest\n");
    exit(2);
}

int main(int argc, char **argv)
{
    static struct option lo[] = {
        {"role", 1, 0, 'r'}, {"peer", 1, 0, 'p'}, {"bind", 1, 0, 'b'}, {"ctl-port", 1, 0, 'c'},
        {"psk-file", 1, 0, 'k'}, {"queue", 1, 0, 'q'}, {"selftest", 0, 0, 't'}, {0, 0, 0, 0}};
    const char *role = NULL, *pskf = NULL;
    int o;
    strcpy(g_ctx.cfg.bind, "0.0.0.0");
    g_ctx.cfg.ctl_port = 9000;
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    while ((o = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (o) {
        case 'r': role = optarg; break;
        case 'p': snprintf(g_ctx.cfg.peer, sizeof g_ctx.cfg.peer, "%s", optarg); break;
        case 'b': snprintf(g_ctx.cfg.bind, sizeof g_ctx.cfg.bind, "%s", optarg); break;
        case 'c': g_ctx.cfg.ctl_port = atoi(optarg); break;
        case 'k': pskf = optarg; break;
        case 'q': g_ctx.cfg.queue = atoi(optarg); break;
        case 't': selftest(); return 0;
        default: usage();
        }
    }
    if (!role || !pskf) usage();
    FILE *f = fopen(pskf, "rb");
    if (!f) { perror(pskf); return 1; }
    size_t n = fread(g_ctx.psk, 1, sizeof g_ctx.psk, f);
    fclose(f);
    size_t st = 0;
    while (n && isspace(g_ctx.psk[n - 1])) n--;
    while (st < n && isspace(g_ctx.psk[st])) st++;
    memmove(g_ctx.psk, g_ctx.psk + st, n - st);
    g_ctx.pl = n - st;
    if (!g_ctx.pl) { fprintf(stderr, "empty PSK file\n"); return 1; }

    pthread_t th;
    if (!strcmp(role, "responder")) pthread_create(&th, NULL, serve_thread, NULL);
    else if (!strcmp(role, "initiator")) {
        if (!g_ctx.cfg.peer[0]) usage();
        pthread_create(&th, NULL, initiate_thread, NULL);
    } else usage();
#ifdef NO_NFQ
    fprintf(stderr, "built without NFQUEUE support (NO_NFQ)\n");
    return 1;
#else
    run_queue(g_ctx.cfg.queue);
    return 0;
#endif
}
