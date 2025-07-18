#include "nts_crypto.h"

#include <assert.h>
#include <gcrypt.h>

static const struct NTS_AEAD_param supported_algos[] = {
	{ NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
	{ NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
	{ NTS_AEAD_AES_SIV_CMAC_384, 384/8, 16, 16, true, false, "AES-192-SIV" },
	{ NTS_AEAD_AES_128_GCM_SIV,  128/8, 16, 12, false, true, "AES-128-GCM-SIV" },
	{ NTS_AEAD_AES_256_GCM_SIV,  256/8, 16, 12, false, true, "AES-256-GCM-SIV" },
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

static int process_assoc_data(
	gcry_cipher_hd_t handle,
	const associated_data *info,
	const struct NTS_AEAD_param *aead
) {
	/* process the associated data and nonce first */
	const associated_data *last = NULL;
	if(aead->nonce_is_iv) {
		/* workaround for the GCM-SIV interface, where the IV is set directly */
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

int NTS_encrypt(uint8_t *ctxt,
		const uint8_t *ptxt,
		int ptxt_len,
		const associated_data *info,
		const struct NTS_AEAD_param *aead,
		const uint8_t *key) {

	int result = -1;

	gcry_cipher_hd_t handle;
	check(gcry_cipher_open(&handle, GCRY_CIPHER_AES, gcrypt_mode(aead), 0) == GPG_ERR_NO_ERROR);

	check(gcry_cipher_setkey(handle, key, aead->key_size) == GPG_ERR_NO_ERROR);
	check(process_assoc_data(handle, info, aead));

	uint8_t *tag;
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

int NTS_decrypt(uint8_t *ptxt,
		const uint8_t *ctxt,
		int ctxt_len,
		const associated_data *info,
		const struct NTS_AEAD_param *aead,
		const uint8_t *key) {

	int result = -1;

	gcry_cipher_hd_t handle;
	check(gcry_cipher_open(&handle, GCRY_CIPHER_AES, gcrypt_mode(aead), 0) == GPG_ERR_NO_ERROR);
	check(ctxt_len >= aead->block_size);

	check(gcry_cipher_setkey(handle, key, aead->key_size) == GPG_ERR_NO_ERROR);
	check(process_assoc_data(handle, info, aead));

	const uint8_t *tag;
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
