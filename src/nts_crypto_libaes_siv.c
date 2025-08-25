#include "nts_crypto.h"

#include <string.h>
#include <assert.h>
#include <aes_siv.h>

static const struct NTS_AEADParam
        siv256 = { NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
        siv512 = { NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
        siv384 = { NTS_AEAD_AES_SIV_CMAC_384, 384/8, 16, 16, true, false, "AES-192-SIV" };

const struct NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        switch (id) {
        case NTS_AEAD_AES_SIV_CMAC_256:
                return &siv256;
        case NTS_AEAD_AES_SIV_CMAC_512:
                return &siv512;
        case NTS_AEAD_AES_SIV_CMAC_384:
                return &siv384;
        default:
                return NULL;
        }
}

#define CHECK(expr) if (expr); else goto exit;

int NTS_encrypt(uint8_t *ctxt,
                const uint8_t *ptxt,
                int ptxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                const uint8_t *key) {

        int result = -1;
        const int BLKSIZ = 16;

        AES_SIV_CTX *state = AES_SIV_CTX_new();
        CHECK(state);

        CHECK(AES_SIV_Init(state, key, aead->key_size));

        /* process the associated data first */
        for ( ; info->data; info++)
                CHECK(AES_SIV_AssociateData(state, info->data, info->length));

        /* encrypt data and write tag */
        uint8_t tag[16];
        CHECK(AES_SIV_EncryptFinal(state, tag, ctxt+BLKSIZ, ptxt, ptxt_len));
        memcpy(ctxt, tag, BLKSIZ);

        result = ptxt_len + BLKSIZ;
exit:
        AES_SIV_CTX_free(state);
        return result;
}

int NTS_decrypt(uint8_t *ptxt,
                const uint8_t *ctxt,
                int ctxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                const uint8_t *key) {

        int result = -1;
        const int BLKSIZ = 16;

        AES_SIV_CTX *state = AES_SIV_CTX_new();
        CHECK(state);
        CHECK(ctxt_len >= BLKSIZ);

        CHECK(AES_SIV_Init(state, key, aead->key_size));
        ctxt += BLKSIZ;
        ctxt_len -= BLKSIZ;

        /* process the associated data first */
        for ( ; info->data; info++)
                CHECK(AES_SIV_AssociateData(state, info->data, info->length));

        /* decrypt data */
        uint8_t tag[16];
        memcpy(tag, ctxt - BLKSIZ, BLKSIZ);
        CHECK(AES_SIV_DecryptFinal(state, ptxt, tag, ctxt, ctxt_len));

        result = ctxt_len;
exit:
        AES_SIV_CTX_free(state);
        return result;
}
