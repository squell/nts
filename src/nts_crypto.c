#include "nts_crypto.h"

#include <assert.h>

#define check(expr) if(expr); else goto exit;

#if defined(USE_GCRYPT)

#ifdef USE_LIBAES_SIV
#  error compilation flag USE_LIBAES_SIV and USE_GCRYPT cannot be combined
#endif

#include <gcrypt.h>

static int process_assoc_data(
	gcry_cipher_hd_t handle,
	const associated_data *info,
	const struct NTS_AEAD_param *aead
) {
	/* process the associated data and nonce first */
	const associated_data *last = NULL;
	if(aead->nonce_is_iv) {
		/* workaround for the GCM-SIV interface, where the IV is set directly in
		 * contradiction to the documentation; */
		assert(info->data);
		for(last = info; (last+1)->data != NULL; ) {
			last++;
		}
		check(last->length == aead->nonce_size);
		check(gcry_cipher_setiv(handle, last->data, last->length) == GPG_ERR_NO_ERROR);
	}

	for( ; info->data && info != last; info++) {
		check(gcry_cipher_authenticate(handle, info->data, info->length) == GPG_ERR_NO_ERROR);
	}

	return 1;
exit:
	return 0;
}

static int gcrypt_mode(const struct NTS_AEAD_param *aead) {
	switch(aead->aead_id) {
		case NTS_AEAD_AES_SIV_CMAC_256:
		case NTS_AEAD_AES_SIV_CMAC_384:
		case NTS_AEAD_AES_SIV_CMAC_512:
			return GCRY_CIPHER_MODE_SIV;
		case NTS_AEAD_AES_128_GCM_SIV:
		case NTS_AEAD_AES_256_GCM_SIV:
			return GCRY_CIPHER_MODE_GCM_SIV;
		default:
			assert(!"unreachable");
	}
}

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;

	gcry_cipher_hd_t handle;
	check(gcry_cipher_open(&handle, GCRY_CIPHER_AES, gcrypt_mode(aead), 0) == GPG_ERR_NO_ERROR);

	check(gcry_cipher_setkey(handle, key, aead->key_size) == GPG_ERR_NO_ERROR);
	check(process_assoc_data(handle, info, aead));

	unsigned char *tag;
	if(aead->tag_first) {
		tag = ctxt;
		ctxt += aead->block_size;
	} else {
		tag = ctxt + ptxt_len;
	}

	check(gcry_cipher_final(handle) == GPG_ERR_NO_ERROR);
	check(gcry_cipher_encrypt(handle, ctxt, ptxt_len+aead->block_size, ptxt, ptxt_len) == GPG_ERR_NO_ERROR);
	check(gcry_cipher_gettag(handle, tag, aead->block_size) == GPG_ERR_NO_ERROR);

	result = ptxt_len + aead->block_size;
exit:
	gcry_cipher_close(handle);
	return result;
}

/* caller should make sure that there is enough room in ptxt for holding the ciphertext */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;

	gcry_cipher_hd_t handle;
	check(gcry_cipher_open(&handle, GCRY_CIPHER_AES, gcrypt_mode(aead), 0) == GPG_ERR_NO_ERROR);
	check(ctxt_len >= aead->block_size);

	check(gcry_cipher_setkey(handle, key, aead->key_size) == GPG_ERR_NO_ERROR);
	check(process_assoc_data(handle, info, aead));

	const unsigned char *tag;
	if(aead->tag_first) {
		tag = ctxt;
		ctxt += aead->block_size;
	} else {
		tag = ctxt + ctxt_len - aead->block_size;
	}
	ctxt_len -= aead->block_size;

	check(gcry_cipher_set_decryption_tag(handle, tag, aead->block_size) == GPG_ERR_NO_ERROR);
	check(gcry_cipher_final(handle) == GPG_ERR_NO_ERROR);
	check(gcry_cipher_decrypt(handle, ptxt, ctxt_len, ctxt, ctxt_len) == GPG_ERR_NO_ERROR);

	result = ctxt_len;
exit:
	gcry_cipher_close(handle);
	return result;
}

#elif !defined(USE_LIBAES_SIV)

#include <openssl/ssl.h>

static int process_assoc_data(
	EVP_CIPHER_CTX *state,
	const associated_data *info,
	const struct NTS_AEAD_param *aead,
	int EVP_CryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*),
	int EVP_CryptUpdate(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int)
) {
	/* process the associated data and nonce first */
	const associated_data *last = NULL;
	if(aead->nonce_is_iv) {
		/* workaround for the OpenSSL GCM-SIV interface, where the IV is set directly in
		 * contradiction to the documentation;
		 * our interface *does* interpret the last AAD item as the siv/nonce
		 */
		assert(info->data);
		for(last = info; (last+1)->data != NULL; ) {
			last++;
		}
		check(last->length == aead->nonce_size);
		check(EVP_CryptInit_ex(state, NULL, NULL, NULL, last->data));
	}

	for( ; info->data && info != last; info++) {
		int len = 0;
		check(EVP_CryptUpdate(state, NULL, &len, info->data, info->length));
		assert((size_t)len == info->length);
	}

	return 1;
exit:
	return 0;
}

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *info, const struct NTS_AEAD_param *aead, const unsigned char *key) {
	int result = -1;
	int len;

	EVP_CIPHER *cipher = NULL;
	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	check(state);

	check((cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL)));

	unsigned char *ctxt_start = ctxt;
	unsigned char *tag;
	if(aead->tag_first) {
		tag = ctxt;
		ctxt += aead->block_size;
	} else {
		tag = ctxt + ptxt_len;
	}

	check(EVP_EncryptInit_ex(state, cipher, NULL, key, NULL));
	check(process_assoc_data(state, info, aead, EVP_EncryptInit_ex, EVP_EncryptUpdate));

	/* encrypt data */
	check(EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len));
	assert(len <= ptxt_len);
	ctxt += len;

	check(EVP_EncryptFinal_ex(state, ctxt, &len));
	assert(len <= aead->block_size);
	ctxt += len;
	assert(ctxt - ctxt_start == ptxt_len + aead->tag_first * aead->block_size);

	/* append/prepend the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, aead->block_size, tag));

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

	/* set the AEAD tag */
	const unsigned char *tag;
	if(aead->tag_first) {
		tag = ctxt;
		ctxt += aead->block_size;
	} else {
		tag = ctxt + ctxt_len - aead->block_size;
	}
	ctxt_len -= aead->block_size;

	check(EVP_DecryptInit_ex(state, cipher, NULL, key, NULL));
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, aead->block_size, (unsigned char*)tag));

	check(process_assoc_data(state, info, aead, EVP_DecryptInit_ex, EVP_DecryptUpdate));

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

#include <aes_siv.h>

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
