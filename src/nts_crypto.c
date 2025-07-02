#include "nts_crypto.h"

#ifdef USE_LIBAES_SIV
#  include <aes_siv.h>
#else
#  define OPENSSL_WORKAROUND
#endif
#include <assert.h>

/* we use this constant to mark which mentions of 16 refer to the AES cipher block size and which ones don't */
#define BLKSIZ 16

#define check(expr) if(expr); else goto exit;

#ifndef USE_LIBAES_SIV

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_query *nts) {
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

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_query *nts) {
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
