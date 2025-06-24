#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "nts.h"
#include "nts_extfields.h"

int main(int argc, char **argv) {
	(void)argc;
	int file = open(argv[1], O_RDONLY);
	unsigned char buffer[1280];
	int len = read(file, buffer, 1280);
	int aead_id = NTS_AEAD_AES_SIV_CMAC_256;

	struct NTS nts = (struct NTS) {
#ifndef USE_LIBAES_SIV
		.cipher = NTS_AEAD_cipher(aead_id),
#else
		.key_len = NTS_AEAD_key_size(aead_id),
#endif
		.c2s_key = (void*)"01234567890abcdef",
		.s2c_key = (void*)"01234567890abcdef",
	};

	struct NTS_response rec;
        (void) NTS_decode_response(buffer, len, &rec);

//        struct NTS_receipt rcpt = { 0, };
//        (void) parse_nts_fields(&buffer, len, &nts, &rcpt);

	return 0;
}
