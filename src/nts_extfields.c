#include <sys/types.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nts_extfields.h"

typedef struct {
        unsigned char *data;
        unsigned char *data_end;
} slice;

static size_t capacity(const slice *slice) {
        return slice->data_end - slice->data;
}

static int write_ntp_ext_field(slice *buf, uint16_t type, void *contents, uint16_t len, uint16_t size) {
	/* enforce minimum size */
	if(size < len+4) size = len+4;
	/* pad to a dword boundary */
	unsigned padlen = (size+3) & ~3;

	if(capacity(buf) < padlen) {
		return 0;
	}

	memmove(buf->data+4, contents, len);
	type = htons(type);
	memcpy(buf->data, &type, 2);
	len = htons(len+4);
	memcpy(buf->data+2, &len, 2);

	buf->data += padlen;
	return padlen;
}

/* note: we use this unconventonial way of passing a pointer to let the compiler check array bounds in a limited way */

#define check(expr) if(expr); else return 0;

/* called should make sure that there is enough room in ptxt for holding the plaintext-padded-to-block size + one additional block */
static int write_encrypted_fields(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const slice *info, const struct NTS *nts) {
	unsigned char *ctxt_start = ctxt;
	int len;

	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	assert(state);

	check(EVP_EncryptInit_ex(state, nts->cipher, NULL, nts->c2s_key, NULL));
	/* leave room for the tag */
	ctxt += 16;

	/* process the associated data first */
	for( ; info->data; info++) {
		check(EVP_EncryptUpdate(state, NULL, &len, info->data, capacity(info)));
		assert((size_t)len == capacity(info));
	}

	/* encrypt data */
	check(EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len));
	assert(len == ptxt_len);
	ctxt += len;

	check(EVP_EncryptFinal_ex(state, ctxt, &len));
	assert(len < 16);
	ctxt += len;

	/* append the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, 16, ctxt_start));

	EVP_CIPHER_CTX_free(state);

	return ctxt - ctxt_start;
}

enum extfields {
	UniqueIdentifier = 0x0104,
	Cookie           = 0x0204,
	AuthEncExtFields = 0x0404,
	NoOpField        = 0x8200,
};

int add_nts_fields(unsigned char (*base)[1280], const struct NTS *nts) {
	slice buf = { *base, *base + 1280 };

	/* skip beyond regular ntp portion */
	buf.data += 48;

	/* generate unique identifier */
	unsigned char rand[32];
	getrandom(rand, sizeof(rand), 0);
	check(write_ntp_ext_field(&buf, UniqueIdentifier, rand, sizeof(rand), 16));

	/* write cookie field */
	check(write_ntp_ext_field(&buf, Cookie, nts->cookie.data, nts->cookie.length, 16));

	/* --- cobble together the extension fields extension field --- */

	unsigned char const nonce_len = 16; /* NTS servers want this to be 16 */
	unsigned char EF[64] = { 0, nonce_len, 0, 0, };
	assert((nonce_len & 3) == 0);

#ifndef NO_WORKAROUND
	/* bug in OpenSSL: https://github.com/openssl/openssl/issues/26580,
	   which means that a ciphertext HAS TO BE PRESENT */
	unsigned char plain_text[4];
	slice ptxt = { plain_text, plain_text+sizeof(plain_text) };
	int ptxt_len = write_ntp_ext_field(&ptxt, NoOpField, NULL, 0, 0);
#else
	unsigned char *const plain_text = NULL;
	int ptxt_len = 0;
#endif

	/* generate the nonce */
	getrandom(EF+4, nonce_len, 0);

	unsigned char *EF_payload = EF+4+nonce_len;
	slice info[] = {
		{ *base, buf.data },  /* aad */
		{ EF+4, EF_payload }, /* nonce */
		{ NULL },
	};
	uint16_t ctxt_len = write_encrypted_fields(EF_payload, plain_text, ptxt_len, info, nts);

	/* add padding if we used a too-short nonce */
	int ef_len = 4 + ctxt_len + (nonce_len < 16? 16 - nonce_len : nonce_len);

	/* set the ciphertext length */
	ctxt_len = htons(ctxt_len);
	memcpy(EF+2, &ctxt_len, 2);

	check(write_ntp_ext_field(&buf, AuthEncExtFields, EF, ef_len, 28));

	return buf.data - *base;
}
