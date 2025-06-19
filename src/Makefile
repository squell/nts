.PHONY: all clean test
CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11 -Wno-unused-value

all: demo qdntp

nts_test: nts_packet.o nts_test.o

test: nts_test
	@./nts_test
	@echo all tests passed

qdntp: qdntp.o sntp.o
	$(CC) $+ -lssl -lcrypto -o $@

demo: demo.o nts_packet.o nts_ssl.o sntp.o nts_extfields.o
	$(CC) $+ -lssl -lcrypto -o $@

clean:
	rm -f a.out *.o demo qdntp nts_test

demo.o: demo.c nts.h sntp.h nts_extfields.h
nts_extfields.o: nts_extfields.c sntp.h nts.h nts_extfields.h
nts_packet.o: nts_packet.c nts.h
nts_ssl.o: nts_ssl.c nts.h
nts_test.o: nts_test.c nts.h
qdntp.o: qdntp.c sntp.h nts.h nts_extfields.h
sntp.o: sntp.c sntp.h nts.h nts_extfields.h
