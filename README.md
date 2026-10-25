# Inline AES-GCM TCP payload protection (prototype, C)

    PC1 -> Device1 ==(protected TCP, same IP/TCP headers)==> Device2 -> PC2

Files: `secure_link.c`, `Makefile`, `setup_rules.sh`.

## Build (both devices)
    sudo apt install build-essential libssl-dev libnetfilter-queue-dev iptables ethtool
    make                 # builds ./secure_link
    make selftest        # optional: needs only libssl-dev, no root, no network setup

## Run (root)
1. Same secret on both devices (authenticates the DH exchange, prevents MITM):
   `head -c 32 /dev/urandom | xxd -p > psk.txt` on one, copy to the other.
2. Device2: `./setup_rules.sh eth1 eth0 10.0.2.0/24 10.0.1.0/24 8080`
   `sudo ./secure_link --role responder --psk-file psk.txt`
3. Device1: `./setup_rules.sh eth0 eth1 10.0.1.0/24 10.0.2.0/24 8080`
   `sudo ./secure_link --role initiator --peer <Device2 IP> --psk-file psk.txt`
4. PC1 routes PC2's network via Device1, PC2 routes back via Device2. Test with
   `nc -l 8080` on PC2 and `nc 10.0.2.2 8080` on PC1; tcpdump between the devices shows ciphertext.

Options: `--bind IP` (responder listen address), `--ctl-port 9000`, `--queue 0` (must match setup_rules.sh).
Until the handshake completes, protected data packets are dropped (fail closed).

## Design
- Handshake (TCP/9000, device to device): X25519 DH, HMAC-SHA256 with the PSK over both public keys
  and nonces, HKDF-SHA256 to two AES-256 keys + two 4-byte salts (one pair per direction).
- Per packet: only the TCP payload becomes `ciphertext || 16-byte tag`. IP/TCP headers kept;
  IP length, IP checksum and TCP checksum recomputed. No UDP, no custom header.
- Authenticated (AAD): src/dst IP, ports, seq, ack.
- Nonce: 4-byte directional salt || 64-bit counter, incremented on every encryption (retransmits
  too); sending stops at 2^48 (re-handshake needed). The receiver finds the counter by trial
  decryption in a window (+256 / -64) around the expected value; replays are rejected by a bitmap.
- Packets without payload (SYN, ACK, FIN) pass unchanged.

## Limitations
IPv4 TCP only; fragments dropped; one session (re-key by restarting); single queue/thread;
a loss burst of >256 packets desyncs the counter window; PSK is a stand-in for certificates;
MTU/MSS must leave 16 bytes of room.

## Testing

Assumed layout: PC1 10.0.1.2 - Device1 - Device2 - PC2 10.0.2.2, protected port 8080.
`D1-peer` / `D2-peer` below mean the interface that faces the other device.

### 0. Offline check (no network needed)
    make selftest
Expected last line: `self-test OK (...)`. This covers header preservation, checksums, exact payload
restore, replay / loss / reordering, tamper rejection (tag, ciphertext, seq number), the nonce limit
and a real X25519 handshake over loopback including a wrong-PSK rejection.

### 1. Handshake
Start the responder, then the initiator. Both must print `session established`.
Wrong PSK on one side -> responder prints `handshake rejected: bad authentication`
and the initiator keeps printing `handshake failed, retrying`.

### 2. Data arrives correctly
    PC2$ nc -l 8080 > received.bin          # or: nc -l -p 8080
    PC1$ head -c 20M /dev/urandom > sent.bin; nc 10.0.2.2 8080 < sent.bin
    PC1$ sha256sum sent.bin;  PC2$ sha256sum received.bin     # must match
If it hangs, see Troubleshooting.

### 3. Traffic is really encrypted between the devices
Run a capture on each link while sending `echo "SECRET-HELLO" | nc 10.0.2.2 8080`:
    Device1$ sudo tcpdump -i <D1-LAN-if>  -A -n port 8080     # PC1 side: text "SECRET-HELLO" visible
    Device1$ sudo tcpdump -i <D1-peer-if> -A -n port 8080     # inter-device link: unreadable bytes
    Device2$ sudo tcpdump -i <D2-LAN-if>  -A -n port 8080     # PC2 side: text visible again
Also check, on the inter-device link, that:
- same IPs, ports, seq and ack as on the LAN side (headers unchanged, no UDP, no extra header);
- each data packet is exactly 16 bytes longer (`length N` vs `length N+16`);
- the same message sent twice gives different ciphertext (new nonce each time).
Use `-vv` to see `cksum 0x.... (correct)` on the receiving side. Checksums of packets captured on the
*sending* machine can show "incorrect" because of NIC offload; the script disables offloads, and the
receiving side is what counts.

### 4. Fail-closed and negative tests
- Stop `secure_link` on Device2, send data from PC1 -> nothing is delivered and no plaintext appears on the
  inter-device link (iptables rules have no `--queue-bypass`).
- Restart it, restart the initiator -> data flows again.
- Traffic on a port that is not protected (e.g. 9090) passes in clear (control experiment).
- Tamper test (optional): on Device2 run `sudo tcpdump -i <D2-peer-if> -w cap.pcap port 8080`, then with
  scapy resend a captured data packet with one payload byte changed (or the identical packet again);
  it must be dropped and PC2 must not receive it. An unchanged replay is also dropped.

### 5. Throughput / MTU sanity
    PC2$ iperf3 -s -p 8080      PC1$ iperf3 -c 10.0.2.2 -p 8080
Works only if no packet needs fragmenting; `setup_rules.sh` clamps MSS to 1400 for this.
Expect low throughput (single-threaded, per-packet userspace crypto) - it is a prototype.

### Troubleshooting
- Nothing flows: `sudo iptables -t mangle -L FORWARD -v -n` (counters on the MARK/NFQUEUE rules must grow),
  `sysctl net.ipv4.ip_forward` = 1, PCs have the right routes, and `--queue` matches the script (default 0).
- Only one direction works: Device1 and Device2 must be started with the interface arguments in the
  mirrored order shown above, and both sessions come from the same handshake.
- Large transfers stall: lower the MTU on the PCs (`ip link set eth0 mtu 1400`).
- Port 9000 is the control channel between the devices; it must be reachable device-to-device.

## On a Mac
The real data path needs Linux (iptables + NFQUEUE), so the two devices must be Linux machines or
Linux VMs. On macOS you can build and run the offline self-test only:

    xcode-select --install            # compiler (once)
    brew install openssl@3            # https://brew.sh if you do not have Homebrew
    make selftest                     # expected: "self-test OK (...)"

(`make` alone will fail on macOS: libnetfilter_queue does not exist there.)

To try the full setup from a Mac, use Linux VMs (UTM, Parallels, VMware Fusion, VirtualBox) with
Ubuntu: two "device" VMs with two network adapters each, or one Ubuntu VM with network namespaces.
Inside Ubuntu follow the Build / Run / Testing sections above unchanged.
