.PHONY: all clean test fuzz fuzz_ntp fuzz_ntske demo nts_test

CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11
TLS ?= openssl

ifeq ($(TLS), gnutls)
  FINAL_LINK = -lgnutls
  CRYPTO ?= nettle
else ifeq ($(TLS), openssl)
  FINAL_LINK = -lssl -lcrypto
  CRYPTO ?= openssl
else
  $(error "TLS must be either 'openssl' or 'gnutls'")
endif

ifeq ($(CRYPTO),libaes_siv)
  LINK += ../libaes_siv/libaes_siv.a -lcrypto
else ifeq ($(CRYPTO), gcrypt)
  LINK += -lgcrypt
else ifeq ($(CRYPTO), openssl)
  LINK += -lcrypto
else ifeq ($(CRYPTO), nettle)
  LINK += -lnettle
else
  $(error "CRYPTO must be either 'openssl', 'gcrypt', 'libaes_siv' or 'nettle'")
endif

demo: demo_$(TLS).o nts_packet.o nts_$(TLS).o nts_error.o sntp.o nts_extfields.o nts_crypto_$(CRYPTO).o tcp_connect.o
	$(CC) $+ $(LINK) $(FINAL_LINK) -o $@

qdntp: qdntp.o sntp.o nts_extfields.o tcp_connect.o
	$(CC) $+ -o $@

nts_test: nts_packet.o nts_extfields.o nts_test.o nts_crypto_$(CRYPTO).o
	$(CC) $+ $(LINK) -lcrypto -o $@

nts_fuzz: nts_packet.o nts_extfields.o nts_fuzz.o
	$(CC) $+ $(CFLAGS) -o $@

test: nts_test
	@./nts_test
	@echo all tests passed

FUZZTIME ?= 3600
fuzz_ntske: nts_fuzz
	afl-fuzz -V $(FUZZTIME) -i ../fuzz/nts_ke -o out_ntske -G 1280 -D ./nts_fuzz @@ +
	@! test -e ./out_ntske/default/crashes/README.txt

fuzz_ntp: nts_fuzz
	afl-fuzz -V $(FUZZTIME) -i ../fuzz/nts_extfield -o out_ntp -g 48 -G 1280 -D ./nts_fuzz @@
	@! test -e ./out_ntp/default/crashes/README.txt

all: demo qdntp nts_fuzz nts_test \
	nts_openssl.o nts_gnutls.o demo_openssl.o demo_gnutls.o \
	nts_crypto_openssl.o nts_crypto_libaes_siv.o nts_crypto_gcrypt.o nts_crypto_nettle.o

clean:
	rm -f a.out *.o demo qdntp nts_test nts_fuzz *.gcov *.gcno *.gcda

demo_openssl.o: demo.c nts.h nts_extfields.h sntp.h
	$(CC) $(CFLAGS) -o $@ -c $<

demo_gnutls.o: demo.c nts.h nts_extfields.h sntp.h
	$(CC) $(CFLAGS) -DUSE_GNUTLS -o $@ -c $<

nts_openssl.o: nts_tls.c nts.h
	$(CC) $(CFLAGS) -o $@ -c $<
nts_gnutls.o: nts_tls.c nts.h
	$(CC) $(CFLAGS) -DUSE_GNUTLS -o $@ -c $<

nts_crypto_openssl.o: nts_crypto_openssl.c nts_crypto.h nts.h nts_extfields.h
nts_crypto_gcrypt.o: nts_crypto_gcrypt.c nts_crypto.h nts.h nts_extfields.h
nts_crypto_libaes_siv.o: nts_crypto_libaes_siv.c nts_crypto.h nts.h nts_extfields.h
	$(CC) $(CFLAGS) -I../libaes_siv -o $@ -c $<
nts_crypto_nettle.o: nts_crypto_nettle.c nts_crypto.h nts.h nts_extfields.h

nts_error.o: nts.h nts_error.c
nts_extfields.o: nts_extfields.c nts_extfields.h nts.h nts_crypto.h
nts_fuzz.o: nts_fuzz.c nts.h nts_crypto.h nts_extfields.h
nts_packet.o: nts_packet.c nts.h
nts_test.o: nts_test.c nts.h nts_extfields.h nts_crypto.h
qdntp.o: qdntp.c sntp.h
sntp.o: sntp.c sntp.h nts_extfields.h nts.h
