.PHONY: clean test
CFLAGS ?= -Wall -Wextra -pedantic -std=gnu11

demo: demo.o nts.o
	$(CC) $+ -lssl -lcrypto -o $@

nts_test: nts.o nts_test.o

test: nts_test
	@./nts_test
	@echo all tests passed

nts_record.o: nts.c nts.h
demo.o: demo.c nts.h

clean:
	rm demo.o nts.o demo nts_test
