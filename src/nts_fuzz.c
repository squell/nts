#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "nts.h"
#include "nts_crypto.h"
#include "nts_extfields.h"

void eat(volatile const uint8_t* buf, size_t size) {
	if(buf) while(size) (void)buf[size--];
}

/* this program does no sanity checking as it is meant for fuzzing only */
int main(int argc, char **argv) {
	int file = open(argv[1], O_RDONLY);
	uint8_t buffer[1280];
	int len = read(file, buffer, 1280);
	if(len < 48) return 0;

	struct NTS_query nts = (struct NTS_query) {
		.cipher = *NTS_AEAD_param(NTS_AEAD_AES_SIV_CMAC_256),
		.c2s_key = (void*)"01234567890abcdef",
		.s2c_key = (void*)"01234567890abcdef",
	};

	if(argc > 2) {
		/* fuzz the nts ke */
		struct NTS_agreement rec;
		if(NTS_decode_response(buffer, len, &rec) == 0) {
			for(int i = 0; i < 8; i++)
				eat(rec.cookie[i].data, rec.cookie[i].length);
		}
	} else {
		struct NTS_receipt rcpt = { 0, };
		if(NTS_parse_extension_fields(&buffer, len, &nts, &rcpt)) {
			eat(rcpt.new_cookie.data, rcpt.new_cookie.length);
			eat(*rcpt.identifier, 32);
		}
	}

	return 0;
}

/* null cipher */

#define BLKSIZ 16

int NTS_encrypt(uint8_t *ctxt,
		const uint8_t *ptxt,
		int ptxt_len,
		const associated_data *info,
		const struct NTS_AEAD_param *nts,
		const uint8_t *key) {
	(void) info;
	(void) nts;
	(void) key;
	memset(ctxt, 0xEE, BLKSIZ);
	memmove(ctxt+BLKSIZ, ptxt, ptxt_len);
	return ptxt_len + BLKSIZ;
}

int NTS_decrypt(uint8_t *ptxt,
		const uint8_t *ctxt,
		int ctxt_len,
		const associated_data *info,
		const struct NTS_AEAD_param *nts,
		const uint8_t *key) {
	(void) info;
	(void) nts;
	(void) key;
	if(ctxt_len < BLKSIZ) return -1;

	memmove(ptxt, ctxt+16, ctxt_len - BLKSIZ);
	return ctxt_len - BLKSIZ;
}

const struct NTS_AEAD_param* NTS_AEAD_param(NTS_AEAD_algorithm_type id) {
	static struct NTS_AEAD_param param = {
		NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV"
	};
	return id? &param : NULL;
}
