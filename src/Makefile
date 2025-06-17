.PHONY: clean
CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11

demo: demo.o nts.o
	$(CC) $+ -lssl -lcrypto -o $@

nts_record.o: nts.c nts.h
demo.o: demo.c nts.h

clean:
	rm demo.o nts.o demo
