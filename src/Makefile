.PHONY: all clean test fuzz fuzz_ntp fuzz_ntske

SIV ?= LIBAES_SIV

CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11
ifeq (${SIV},LIBAES_SIV)
  CFLAGS += -I../libaes_siv -DUSE_LIBAES_SIV
  LINK += ../libaes_siv/libaes_siv.a
  CRYPTO = crypto_libaes_siv
else
  ifeq (${SIV}, GCRYPT)
    CFLAGS += -DUSE_GCRYPT
    LINK += -lgcrypt
    CRYPTO = crypto_gcrypt
  else
    ifeq (${SIV}, OPENSSL)
      CFLAGS += -DOPENSSL_WORKAROUND
      CRYPTO = crypto
    else
      $(error "SIV must be either OPENSSL, GCRYPT, or LIBAES_SIV")
    endif
  endif
endif

demo: demo.o nts_packet.o nts_ssl.o sntp.o nts_extfields.o nts_${CRYPTO}.o tcp_connect.o
	$(CC) $+ ${LINK} -lssl -lcrypto -o $@

qdntp: qdntp.o sntp.o nts_extfields.o tcp_connect.o
	$(CC) $+ -o $@

nts_test: nts_packet.o nts_extfields.o nts_test.o nts_${CRYPTO}.o
	$(CC) $+ ${LINK} -lssl -lcrypto -o $@

nts_fuzz: nts_packet.o nts_extfields.o nts_fuzz.o
	$(CC) $+ ${CFLAGS} -o $@

test: nts_test
	@./nts_test
	@echo all tests passed

FUZZTIME ?= 3600
fuzz_ntske: nts_fuzz
	afl-fuzz -V ${FUZZTIME} -i ../fuzz/nts_ke -o out_ntske -G 1280 -D ./nts_fuzz @@ +
	@! test -e ./out_ntske/default/crashes/README.txt

fuzz_ntp: nts_fuzz
	afl-fuzz -V ${FUZZTIME} -i ../fuzz/nts_extfield -o out_ntp -g 48 -G 1280 -D ./nts_fuzz @@
	@! test -e ./out_ntp/default/crashes/README.txt

all: demo qdntp nts_fuzz nts_test

clean:
	rm -f a.out *.o demo qdntp nts_test nts_fuzz *.gcov *.gcno *.gcda

demo.o: demo.c nts.h nts_extfields.h sntp.h
nts_${CRYPTO}.o: nts_${CRYPTO}.c nts_crypto.h nts.h nts_extfields.h
nts_extfields.o: nts_extfields.c nts_extfields.h nts.h nts_crypto.h
nts_fuzz.o: nts_fuzz.c nts.h nts_extfields.h
nts_packet.o: nts_packet.c nts.h
nts_ssl.o: nts_ssl.c nts.h
nts_test.o: nts_test.c nts.h nts_extfields.h nts_crypto.h
qdntp.o: qdntp.c sntp.h
sntp.o: sntp.c sntp.h nts_extfields.h nts.h
