#include <assert.h>
#include <syslog.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include "nts_crypto.h"

#if !OPENSSL_VERSION_PREREQ(3,0)
#    error Your OpenSSL version does not support SIV modes, need at least version 3.0.
#endif

#if defined(OPENSSL_WORKAROUND) && OPENSSL_VERSION_PREREQ(3,5)
#    warning The OpenSSL workaround is not necessary.
#endif

static const NTS_AEADParam supported_algos[] = {
        { NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_384, 384/8, 16, 16, true, false, "AES-192-SIV" },
#if OPENSSL_VERSION_PREREQ(3,2)
        { NTS_AEAD_AES_128_GCM_SIV,  128/8, 16, 12, false, true, "AES-128-GCM-SIV" },
        { NTS_AEAD_AES_256_GCM_SIV,  256/8, 16, 12, false, true, "AES-256-GCM-SIV" },
#endif
};

const NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        for (size_t i = 0; i < ELEMENTSOF(supported_algos); i++)
                if (supported_algos[i].aead_id == id)
                        return &supported_algos[i];

        return NULL;
}

/* two function types to aid readability down below and avoid code duplication
 * NOTE: these two signatures are straight from the OpenSSL docs since they are intended
 * to match the EVP_En/DecryptInit_ex and EVP_En/DecryptUpdate functions.
 */

typedef int EVP_CryptInit_func(
                EVP_CIPHER_CTX *ctx,
                const EVP_CIPHER *type,
                ENGINE *impl,
                const uint8_t *key,
                const uint8_t *iv);

typedef int EVP_CryptUpdate_func(
                EVP_CIPHER_CTX* ctx,
                uint8_t *out,
                int *outl,
                const uint8_t *in,
                int inl);

static bool process_assoc_data(
                EVP_CIPHER_CTX *state,
                const struct AssociatedData *info,
                const NTS_AEADParam *aead,
                EVP_CryptInit_func CryptInit_ex,
                EVP_CryptUpdate_func CryptUpdate) {

        int r;

        assert(state);
        assert(info);
        assert(aead);

        /* process the associated data and nonce first */
        const struct AssociatedData *last = NULL;
        if (aead->nonce_is_iv) {
                /* workaround for the OpenSSL GCM-SIV interface, where the IV is set directly in
                 * contradiction to the documentation;
                 * our interface *does* interpret the last AAD item as the siv/nonce
                 */
                assert(info->data);
                for (last = info; (last+1)->data != NULL; )
                        last++;

                if (last->length != aead->nonce_size)
                        goto exit;

                r = CryptInit_ex(state, NULL, NULL, NULL, last->data);
                if (r == 0)
                        goto exit;
        }

        for ( ; info->data && info != last; info++) {
                int len = 0;
                r = CryptUpdate(state, NULL, &len, info->data, info->length);
                if (r == 0)
                        goto exit;

                assert((size_t)len == info->length);
        }

        return true;
exit:
        return false;
}

int NTS_encrypt(uint8_t *ctxt,
                size_t ctxt_len,
                const uint8_t *ptxt,
                size_t ptxt_len,
                const struct AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key) {

        int result = -EINVAL;
        int r;
        int len;

        assert(ctxt);
        assert(ctxt_len <= (size_t)INT_MAX); /* OpenSSL expects an int */
        assert(ptxt);
        assert(ptxt_len <= (size_t)INT_MAX); /* same */
        assert(info);
        assert(aead);
        assert(key);

        EVP_CIPHER *cipher = NULL;
        EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
        if (!state)
                return -ENOMEM;

        cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL);
        if (!cipher)
                return EVP_CIPHER_CTX_free(state), -EINVAL;

        /* check that the ciphertext length is large enough */
        assert(ptxt_len <= SIZE_MAX - aead->block_size);
        if (ctxt_len < ptxt_len + aead->block_size)
                goto exit;

        uint8_t *ctxt_start = ctxt;
        uint8_t *tag;
        if (aead->tag_first) {
                tag = ctxt;
                ctxt += aead->block_size;
        } else
                tag = ctxt + ptxt_len;

        r = EVP_EncryptInit_ex(state, cipher, NULL, key, NULL);
        if (r == 0)
                goto exit;

        r = process_assoc_data(state, info, aead, EVP_EncryptInit_ex, EVP_EncryptUpdate);
        if (r == 0)
                goto exit;

        /* encrypt data */
        r = EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len);
        if (r == 0)
                goto exit;

        assert(len <= (int) ptxt_len);
        ctxt += len;

        r = EVP_EncryptFinal_ex(state, ctxt, &len);
        if (r == 0)
                goto exit;

        assert(len <= aead->block_size);
        ctxt += len;
        assert(ctxt - ctxt_start == (ptrdiff_t) ptxt_len + aead->tag_first * aead->block_size);

        /* append/prepend the AEAD tag */
        r = EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, aead->block_size, tag);
        if (r == 0)
                goto exit;

        result = ptxt_len + aead->block_size;
exit:
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(state);
        return result;
}

int NTS_decrypt(uint8_t *ptxt,
                size_t ptxt_len,
                const uint8_t *ctxt,
                size_t ctxt_len,
                const struct AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key) {

        int result = -EINVAL;
        int r;
        int len;

        assert(ptxt);
        assert(ptxt_len <= (size_t)INT_MAX); /* OpenSSL expects an int */
        assert(ctxt);
        assert(ctxt_len <= (size_t)INT_MAX); /* same */
        assert(info);
        assert(aead);
        assert(key);

        EVP_CIPHER *cipher = NULL;
        EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
        if (!state)
                return -ENOMEM;

        /* check that the ciphertext size is valid */
        if (ctxt_len < aead->block_size || ptxt_len < ctxt_len - aead->block_size)
                return -EINVAL;

        cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL);
        if (!cipher)
                return EVP_CIPHER_CTX_free(state), -EINVAL;

        /* set the AEAD tag */
        const uint8_t *tag;
        if (aead->tag_first) {
                tag = ctxt;
                ctxt += aead->block_size;
        } else
                tag = ctxt + ctxt_len - aead->block_size;

        ctxt_len -= aead->block_size;

        r = EVP_DecryptInit_ex(state, cipher, NULL, key, NULL);
        if (r == 0)
                goto exit;

        r = EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, aead->block_size, (uint8_t*)tag);
        if (r == 0)
                goto exit;

        r = process_assoc_data(state, info, aead, EVP_DecryptInit_ex, EVP_DecryptUpdate);
        if (r == 0)
                goto exit;

        uint8_t *ptxt_start = ptxt;

        /* decrypt data */
        r = EVP_DecryptUpdate(state, ptxt, &len, ctxt, ctxt_len);
        if (r == 0)
                goto exit;

        assert(len <= (int) ctxt_len);
        ptxt += len;

        r = EVP_DecryptFinal_ex(state, ptxt, &len);
        if (r == 0)
                goto exit;

        assert(len <= aead->block_size);
        ptxt += len;

        assert(ptxt - ptxt_start == (ptrdiff_t) ctxt_len);

        result = ctxt_len;
exit:
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(state);
        return result;
}
