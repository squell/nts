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
#define STUB(name) int name() { return -1; }

/* openssl functions */
STUB(EVP_EncryptInit_ex)
STUB(EVP_DecryptInit_ex)
STUB(EVP_EncryptUpdate)
STUB(EVP_DecryptUpdate)
STUB(EVP_EncryptFinal_ex)
STUB(EVP_DecryptFinal_ex)
STUB(EVP_CIPHER_CTX_new)
STUB(EVP_CIPHER_CTX_ctrl)
STUB(EVP_CIPHER_CTX_free)

/* libaes_siv functions */
STUB(AES_SIV_Init)
STUB(AES_SIV_AssociateData)
STUB(AES_SIV_EncryptFinal)
STUB(AES_SIV_DecryptFinal)
STUB(AES_SIV_CTX_new)
STUB(AES_SIV_CTX_free)
