#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "nts.h"
#include "nts_extfields.h"

/* this program does no sanity checking as it is meant for fuzzing only */

int main(int argc, char **argv) {
	int file = open(argv[1], O_RDONLY);
	unsigned char buffer[1280];
	int len = read(file, buffer, 1280);
	if(len < 48) return 0;
	int aead_id = NTS_AEAD_AES_SIV_CMAC_256;

	struct NTS_query nts = (struct NTS_query) {
#ifndef USE_LIBAES_SIV
		.cipher = NULL,
#endif
		.key_len = NTS_AEAD_key_size(aead_id),
		.c2s_key = (void*)"01234567890abcdef",
		.s2c_key = (void*)"01234567890abcdef",
	};

	if(argc > 2) {
		/* fuzz the nts ke */
		struct NTS_agreement rec;
		(void) NTS_decode_response(buffer, len, &rec);
	} else {
		struct NTS_receipt rcpt = { 0, };
		(void) NTS_parse_extension_fields(&buffer, len, &nts, &rcpt);
	}

	return 0;
}

/* null cipher */

#define BLKSIZ 16

int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const void *info, const void *nts) {
	(void) info;
	(void) nts;
	memset(ctxt, 0xEE, BLKSIZ);
	memmove(ctxt+BLKSIZ, ptxt, ptxt_len);
	return ptxt_len + BLKSIZ;
}

int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const void *info, const void *nts) {
	(void) info;
	(void) nts;
	if(ctxt_len < BLKSIZ) return -1;

	memmove(ptxt, ctxt+16, ctxt_len - BLKSIZ);
	return ctxt_len - BLKSIZ;
}
