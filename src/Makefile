.PHONY: all clean test fuzz fuzz_ntp fuzz_ntske

CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11
CRYPTO ?= openssl

ifeq ($(CRYPTO),libaes_siv)
  LINK += ../libaes_siv/libaes_siv.a
else ifeq ($(CRYPTO), gcrypt)
  LINK += -lgcrypt
else ifeq ($(CRYPTO), openssl)
  # we already link to OpenSSL
else
  $(error "CRYPTO must be either 'openssl', 'gcrypt', or 'libaes_siv'")
endif

demo: demo.o nts_packet.o nts_ssl.o sntp.o nts_extfields.o nts_crypto_$(CRYPTO).o tcp_connect.o
	$(CC) $+ $(LINK) -lssl -lcrypto -o $@

qdntp: qdntp.o sntp.o nts_extfields.o tcp_connect.o
	$(CC) $+ -o $@

nts_test: nts_packet.o nts_extfields.o nts_test.o nts_crypto_$(CRYPTO).o
	$(CC) $+ $(LINK) -lssl -lcrypto -o $@

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

all: demo qdntp nts_fuzz nts_test nts_crypto.o nts_crypto_libaes_siv.o nts_crypto_gcrypt.o

clean:
	rm -f a.out *.o demo qdntp nts_test nts_fuzz *.gcov *.gcno *.gcda

demo.o: demo.c nts.h nts_extfields.h sntp.h
nts_crypto_openssl.o: nts_crypto_openssl.c nts_crypto.h nts.h nts_extfields.h
nts_crypto_gcrypt.o: nts_crypto_gcrypt.c nts_crypto.h nts.h nts_extfields.h
nts_crypto_libaes_siv.o: nts_crypto_libaes_siv.c nts_crypto.h nts.h nts_extfields.h
	$(CC) $(CFLAGS) -I../libaes_siv -o $@ -c $<

nts_extfields.o: nts_extfields.c nts_extfields.h nts.h nts_crypto.h
nts_fuzz.o: nts_fuzz.c nts.h nts_extfields.h
nts_packet.o: nts_packet.c nts.h
nts_ssl.o: nts_ssl.c nts.h
nts_test.o: nts_test.c nts.h nts_extfields.h nts_crypto.h
qdntp.o: qdntp.c sntp.h
sntp.o: sntp.c sntp.h nts_extfields.h nts.h
