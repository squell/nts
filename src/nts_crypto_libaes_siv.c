#include "nts_crypto.h"

#include <assert.h>
#include <aes_siv.h>

#define check(expr) if(expr); else goto exit;

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;
	const int BLKSIZ = 16;

	AES_SIV_CTX *state = AES_SIV_CTX_new();
	check(state);

	check(AES_SIV_Init(state, key, aead->key_size));

	/* process the associated data first */
	for( ; info->data; info++) {
		check(AES_SIV_AssociateData(state, info->data, info->length));
	}

	/* encrypt data and write tag */
	unsigned char tag[16];
	check(AES_SIV_EncryptFinal(state, tag, ctxt+BLKSIZ, ptxt, ptxt_len));
	memcpy(ctxt, tag, BLKSIZ);

	result = ptxt_len + BLKSIZ;
exit:
	AES_SIV_CTX_free(state);
	return result;
}

/* caller should make sure that there is enough room in ptxt for holding the ciphertext */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;
	const int BLKSIZ = 16;

	AES_SIV_CTX *state = AES_SIV_CTX_new();
	check(state);
	check(ctxt_len >= BLKSIZ);

	check(AES_SIV_Init(state, key, aead->key_size));
	ctxt += BLKSIZ;
	ctxt_len -= BLKSIZ;

	/* process the associated data first */
	for( ; info->data; info++) {
		check(AES_SIV_AssociateData(state, info->data, info->length));
	}

	/* decrypt data */
	unsigned char tag[16];
	memcpy(tag, ctxt - BLKSIZ, BLKSIZ);
	check(AES_SIV_DecryptFinal(state, ptxt, tag, ctxt, ctxt_len));

	result = ctxt_len;
exit:
	AES_SIV_CTX_free(state);
	return result;
}
