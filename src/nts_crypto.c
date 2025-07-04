#include "nts_crypto.h"

#ifdef USE_LIBAES_SIV
#  include <aes_siv.h>
#else
#  include <openssl/ssl.h>
#endif
#include <assert.h>

#define check(expr) if(expr); else goto exit;

#ifndef USE_LIBAES_SIV

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;
	int len;

	EVP_CIPHER *cipher = NULL;
	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	check(state);

	check((cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL)));

	check(EVP_EncryptInit_ex(state, cipher, NULL, key, NULL));

	/* process the associated data first */
	for( ; info->data; info++) {
		check(EVP_EncryptUpdate(state, NULL, &len, info->data, info->length));
		assert((size_t)len == info->length);
	}

	unsigned char *ctxt_start = ctxt;
	ctxt += aead->block_size;

	/* encrypt data */
	check(EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len));
	assert(len <= ptxt_len);
	ctxt += len;

	check(EVP_EncryptFinal_ex(state, ctxt, &len));
	assert(len <= aead->block_size);
	ctxt += len;
	assert(ctxt - ctxt_start == ptxt_len + aead->block_size);

	/* prepend the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, aead->block_size, ctxt_start));

	result = ptxt_len + aead->block_size;
exit:
	EVP_CIPHER_CTX_free(state);
	EVP_CIPHER_free(cipher);
	return result;
}

/* caller should make sure that there is enough room in ptxt for holding the ciphertext */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;
	int len;

	EVP_CIPHER *cipher = NULL;
	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	check(state);
	check(ctxt_len >= aead->block_size);

	check((cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL)));

	check(EVP_DecryptInit_ex(state, cipher, NULL, key, NULL));

	/* set the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, aead->block_size, (unsigned char*)ctxt));
	ctxt += aead->block_size;
	ctxt_len -= aead->block_size;

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
	assert(len <= aead->block_size);
	ptxt += len;
	assert(ptxt - ptxt_start == ctxt_len);

	result = ctxt_len;
exit:
	EVP_CIPHER_CTX_free(state);
	EVP_CIPHER_free(cipher);
	return result;
}

#else

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
	check(AES_SIV_EncryptFinal(state, ctxt, ctxt+BLKSIZ, ptxt, ptxt_len));

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
	check(AES_SIV_DecryptFinal(state, ptxt, ctxt - BLKSIZ, ctxt, ctxt_len));

	result = ctxt_len;
exit:
	AES_SIV_CTX_free(state);
	return result;
}

#endif
