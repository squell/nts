#include <sys/types.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef USE_LIBAES_SIV
#  include <aes_siv.h>
#else
#  define OPENSSL_WORKAROUND
#endif

#include "nts_extfields.h"

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

/* we use this constant to mark which mentions of 16 refer to the AES cipher block size and which ones don't */
#define BLKSIZ 16

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
	uint16_t padded_len = (size+3) & ~3;
	int padding = padded_len - (len+4);

	if(capacity(buf) < padded_len) {
		return 0;
	}

	memmove(buf->data+4, contents, len);
	type = htons(type);
	memcpy(buf->data, &type, 2);
	len = htons(padded_len);
	memcpy(buf->data+2, &len, 2);

	buf->data += padded_len;
	memset(buf->data - padding, 0, padding);
	return padded_len;
}

#define check(expr) if(expr); else goto exit;

/* re-use this datastructure */
typedef struct NTS_cookie associated_data;

#ifndef USE_LIBAES_SIV

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
static int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_query *nts) {
	int result = -1;
	int len;

	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	check(state);

	check(EVP_EncryptInit_ex(state, nts->cipher, NULL, nts->c2s_key, NULL));

	/* process the associated data first */
	for( ; info->data; info++) {
		check(EVP_EncryptUpdate(state, NULL, &len, info->data, info->length));
		assert((size_t)len == info->length);
	}

	unsigned char *ctxt_start = ctxt;
	ctxt += BLKSIZ;

	/* encrypt data */
	check(EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len));
	assert(len <= ptxt_len);
	ctxt += len;

	check(EVP_EncryptFinal_ex(state, ctxt, &len));
	assert(len <= BLKSIZ);
	ctxt += len;
	assert(ctxt - ctxt_start == ptxt_len + BLKSIZ);

	/* prepend the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, BLKSIZ, ctxt_start));

	result = ptxt_len + BLKSIZ;
exit:
	EVP_CIPHER_CTX_free(state);
	return result;
}

#else

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
static int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_query *nts) {
	int result = -1;
	AES_SIV_CTX *state = AES_SIV_CTX_new();
	check(state);

	check(AES_SIV_Init(state, nts->c2s_key, nts->key_len));

	/* process the associated data first */
	for( ; info->data; info++) {
		check(AES_SIV_AssociateData(state, info->data, info->length));
	}

	/* encrypt data and write tag */
	check(AES_SIV_EncryptFinal(state, ctxt, ctxt+BLKSIZ, ptxt, ptxt_len));

	result = ptxt_len + BLKSIZ;
exit:
	AES_SIV_CTX_free(state);
	return result;
}

#endif

enum extfields {
	UniqueIdentifier = 0x0104,
	Cookie           = 0x0204,
	AuthEncExtFields = 0x0404,
	NoOpField        = 0x0200,
};

int NTS_add_extension_fields(unsigned char (*dest)[1280], const struct NTS_query *nts, unsigned char (*uniq_id)[32]) {
	slice buf = { *dest, *dest + 1280 };

	/* skip beyond regular ntp portion */
	buf.data += 48;

	/* generate unique identifier */
	unsigned char rand_buf[32], *rand = *(uniq_id? uniq_id : &rand_buf);
	getrandom(rand, sizeof(rand_buf), 0);
	check(write_ntp_ext_field(&buf, UniqueIdentifier, rand, sizeof(rand_buf), 16));

	/* write cookie field */
	check(write_ntp_ext_field(&buf, Cookie, nts->cookie.data, nts->cookie.length, 16));

	/* --- cobble together the extension fields extension field --- */

	unsigned char const nonce_len = 16; /* NTS servers want this to be 16 */
	unsigned char EF[64] = { 0, nonce_len, 0, 0, }; /* 64 bytes are plenty */
	assert((nonce_len & 3) == 0);

#ifdef OPENSSL_WORKAROUND
	/* bug in OpenSSL: https://github.com/openssl/openssl/issues/26580,
	   which means that a ciphertext HAS TO BE PRESENT */
	unsigned char plain_text[4];
	slice ptxt = { plain_text, plain_text+sizeof(plain_text) };
	int ptxt_len = write_ntp_ext_field(&ptxt, NoOpField, plain_text, 0, 0);
#else
	unsigned char *const plain_text = NULL;
	int ptxt_len = 0;
#endif

	/* generate the nonce */
	getrandom(EF+4, nonce_len, 0);
	unsigned char *EF_payload = EF+4+nonce_len;

	associated_data info[] = {
		{ *dest, buf.data - *dest },  /* aad */
		{ EF+4,  nonce_len },         /* nonce */
		{ NULL },
	};

	assert((int)sizeof(EF) - (EF_payload - EF) >= ptxt_len + BLKSIZ);
	int ctxt_len = NTS_encrypt(EF_payload, plain_text, ptxt_len, info, nts);
	check(ctxt_len >= 0);

	/* add padding if we used a too-short nonce */
	int ef_len = 4 + ctxt_len + (nonce_len < 16? 16 - nonce_len : nonce_len);

	/* set the ciphertext length */
	ctxt_len = htons(ctxt_len);
	memcpy(EF+2, &ctxt_len, 2);

	check(write_ntp_ext_field(&buf, AuthEncExtFields, EF, ef_len, 28));

	return buf.data - *dest;
exit:
	return 0;
}

#ifndef USE_LIBAES_SIV

/* caller should make sure that there is enough room in ptxt for holding the ciphertext */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *info, const struct NTS_query *nts) {
	int result = -1;
	int len;

	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	check(state);
	check(ctxt_len >= BLKSIZ);

	check(EVP_DecryptInit_ex(state, nts->cipher, NULL, nts->s2c_key, NULL));

	/* set the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, BLKSIZ, (unsigned char*)ctxt));
	ctxt += BLKSIZ;
	ctxt_len -= BLKSIZ;

	/* process the associated data first */
	for( ; info->data; info++) {
		check(EVP_DecryptUpdate(state, NULL, &len, info->data, info->length));
		assert((size_t)len == info->length);
	}

	unsigned char *ptxt_start = ptxt;

	/* decrypt data */
	check(EVP_DecryptUpdate(state, ptxt, &len, ctxt, ctxt_len));
	assert(len <= ctxt_len);
	ptxt += len;

	check(EVP_DecryptFinal_ex(state, ptxt, &len));
	assert(len <= BLKSIZ);
	ptxt += len;
	assert(ptxt - ptxt_start == ctxt_len);

	result = ctxt_len;
exit:
	EVP_CIPHER_CTX_free(state);
	return result;
}

#else

/* caller should make sure that there is enough room in ptxt for holding the ciphertext */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *info, const struct NTS_query *nts) {
	int result = -1;
	AES_SIV_CTX *state = AES_SIV_CTX_new();
	check(state);
	check(ctxt_len >= BLKSIZ);

	check(AES_SIV_Init(state, nts->s2c_key, nts->key_len));
	ctxt += BLKSIZ;
	ctxt_len -= BLKSIZ;

	/* process the associated data first */
	for( ; info->data; info++) {
		check(AES_SIV_AssociateData(state, info->data, info->length));
	}

	/* decrypt data */
	check(AES_SIV_DecryptFinal(state, ptxt, ctxt - BLKSIZ, ctxt, ctxt_len));

	result = ctxt_len;
exit:
	AES_SIV_CTX_free(state);
	return result;
}

#endif

/* caller checks memory bounds */
static void decode_hdr(uint16_t *restrict a, uint16_t *restrict b, unsigned char *bytes) {
	memcpy(a, bytes, 2), memcpy(b, bytes+2, 2);
	*a = ntohs(*a), *b = ntohs(*b);
}

int NTS_parse_extension_fields(unsigned char (*src)[1280], size_t src_len, const struct NTS_query *nts, struct NTS_receipt *fields) {
	assert(src_len >= 48 && src_len <= sizeof(*src));
	slice buf = { *src + 48, *src + src_len };
	int processed = 0;

	while(capacity(&buf) >= 4) {
		uint16_t type, len;
		decode_hdr(&type, &len, buf.data);
		check(len >= 4);
		check(capacity(&buf) >= len);

		switch(type) {
			case UniqueIdentifier:
				check(len - 4 == 32);
				fields->identifier = (unsigned char (*)[32])(buf.data + 4);
				++processed;
				break;
			case AuthEncExtFields: {
				uint16_t nonce_len, ciph_len;
				decode_hdr(&nonce_len, &ciph_len, buf.data + 4);
				check(nonce_len + ciph_len + 8 <= len);
				unsigned char *nonce = buf.data + 8;
				unsigned char *content = nonce + nonce_len;

				associated_data info[] = {
					{ *src, buf.data - *src }, /* aad */
					{ nonce, nonce_len },      /* nonce */
					{ NULL },
				};

				int plain_len = NTS_decrypt(content+BLKSIZ, content, ciph_len, info, nts);
				assert(plain_len < ciph_len);
				check(plain_len >= 0);

				slice plain = { content+BLKSIZ, content+BLKSIZ + plain_len };

				while(capacity(&plain) >= 4) {
					uint16_t type, len;
					decode_hdr(&type, &len, plain.data);
					check(capacity(&plain) >= len);

					/* only care about cookies */
					switch(type) {
						case Cookie:
							fields->new_cookie.data = plain.data + 4;
							fields->new_cookie.length = len - 4;
							break;
						default:
							plain.data += len;
							continue;
					}

					break;
				}

				/* ignore any further fields after this,
				 * since they are not authenticated */
				return processed;
			}

			default:
				/* ignore unknown fields */
				;
		};

		buf.data += len;
	}

exit:
	return 0;
}
