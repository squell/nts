.PHONY: all clean test
CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11 -Wno-unused-value

demo: demo.o nts_packet.o nts_ssl.o
	$(CC) $+ -lssl -lcrypto -o $@

all: demo qdntp nts_test

nts_test: nts_packet.o nts_test.o

test: nts_test
	@./nts_test
	@echo all tests passed

nts_packet.o: nts_packet.c nts.h
nts_ssl.o: nts_ssl.c nts.h
demo.o: demo.c nts.h
qdntp: qdntp.o sntp.o

clean:
	rm *.o demo nts_test
