#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "sntp.h"

int main(int argc, char **argv) {
	if(argc <= 1) {
		puts("qdntp [time server]");
		return 1;
	}

	const char *host = argv[1];
	int port = argv[2]? atoi(argv[2]) : 123;

	double delay, offset;
	ntp_poll(host, port, &delay, &offset);

	printf("roundtrip delay: %g\n", delay);
	printf("offset: %g\n", offset);

	return 0;
}

/* these are here to silence the linker */
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#define STUB(name, val) name() { return val; }

int STUB(NTS_decrypt, -1)
int STUB(NTS_encrypt, -1)
void *STUB(NTS_AEAD_param, NULL)
