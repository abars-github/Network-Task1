CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDLIBS   = -lcrypto -lpthread

# macOS: OpenSSL comes from Homebrew (brew install openssl@3)
ifeq ($(shell uname),Darwin)
OPENSSL ?= $(shell brew --prefix openssl@3 2>/dev/null)
CFLAGS  += -I$(OPENSSL)/include
LDFLAGS += -L$(OPENSSL)/lib
endif

# Linux only: needs libnetfilter-queue-dev
secure_link: secure_link.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS) -lnetfilter_queue

# Linux or macOS: needs only OpenSSL; no root, no network setup
selftest: secure_link.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DNO_NFQ -o secure_link_selftest $< $(LDLIBS)
	./secure_link_selftest --selftest

clean:
	rm -f secure_link secure_link_selftest

.PHONY: selftest clean
