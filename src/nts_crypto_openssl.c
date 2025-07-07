#include "nts_crypto.h"

#include <assert.h>
#include <openssl/ssl.h>

static const struct NTS_AEAD_param supported_algos[] = {
	{ NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
	{ NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
	{ NTS_AEAD_AES_SIV_CMAC_384, 384/8, 16, 16, true, false, "AES-192-SIV" },
#if OPENSSL_VERSION_PREREQ(3,2)
	{ NTS_AEAD_AES_128_GCM_SIV,  128/8, 16, 12, false, true, "AES-128-GCM-SIV" },
	{ NTS_AEAD_AES_256_GCM_SIV,  256/8, 16, 12, false, true, "AES-256-GCM-SIV" },
#endif
};

#define ELEMS(array) (sizeof(array) / sizeof(*array))

const struct NTS_AEAD_param* NTS_AEAD_param(NTS_AEAD_algorithm_type id) {
	for(size_t i=0; i < ELEMS(supported_algos); i++) {
		if(supported_algos[i].aead_id == id) {
			return &supported_algos[i];
		}
	}

	return NULL;
}

#define check(expr) if(expr); else goto exit;

typedef int init_f(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
typedef int upd_f(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);

static int process_assoc_data(
	EVP_CIPHER_CTX *state,
	const associated_data *info,
	const struct NTS_AEAD_param *aead,

	init_f EVP_CryptInit_ex,
	upd_f EVP_CryptUpdate
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

int NTS_encrypt(unsigned char *ctxt,
		const unsigned char *ptxt,
		int ptxt_len,
		const associated_data *info,
		const struct NTS_AEAD_param *aead,
		const unsigned char *key) {

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

int NTS_decrypt(unsigned char *ptxt,
		const unsigned char *ctxt,
		int ctxt_len,
		const associated_data *info,
		const struct NTS_AEAD_param *aead,
		const unsigned char *key) {

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
