#include <sys/types.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nts_extfields.h"

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

#define check(expr) if(expr); else return 0;

/* caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
static int write_encrypted_fields(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const slice *info, const struct NTS *nts) {
        unsigned char *ctxt_start = ctxt;
        int len;

        EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
        assert(state);

        check(EVP_EncryptInit_ex(state, nts->cipher, NULL, nts->c2s_key, NULL));
        /* leave room for the tag */
        ctxt += BLKSIZ;

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
        assert(len < BLKSIZ);
        ctxt += len;

        /* prepend the AEAD tag */
        check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, BLKSIZ, ctxt_start));

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
        unsigned char EF[64] = { 0, nonce_len, 0, 0, }; /* 64 bytes are plenty */
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

        assert((int)sizeof(EF) - (EF_payload - EF) >= ptxt_len + BLKSIZ);
        uint16_t ctxt_len = write_encrypted_fields(EF_payload, plain_text, ptxt_len, info, nts);

        /* add padding if we used a too-short nonce */
        int ef_len = 4 + ctxt_len + (nonce_len < 16? 16 - nonce_len : nonce_len);

        /* set the ciphertext length */
        ctxt_len = htons(ctxt_len);
        memcpy(EF+2, &ctxt_len, 2);

        check(write_ntp_ext_field(&buf, AuthEncExtFields, EF, ef_len, 28));

        return buf.data - *base;
}

/* caller should make sure that there is enough room in ptxt for holding the ciphertext */
static int read_encrypted_fields(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const slice *info, const struct NTS *nts) {
        unsigned char *ptxt_start = ptxt;
        int len;

        EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
        assert(state);

        check(EVP_DecryptInit_ex(state, nts->cipher, NULL, nts->s2c_key, NULL));

        /* set the AEAD tag */
        check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, BLKSIZ, (unsigned char*)ctxt));
        ctxt += BLKSIZ;
        ctxt_len -= BLKSIZ;

        /* process the associated data first */
        for( ; info->data; info++) {
                check(EVP_DecryptUpdate(state, NULL, &len, info->data, capacity(info)));
                assert((size_t)len == capacity(info));
        }

        /* decrypt data */
        check(EVP_DecryptUpdate(state, ptxt, &len, ctxt, ctxt_len));
        assert(len == ctxt_len);
        ptxt += len;

        check(EVP_DecryptFinal_ex(state, ptxt, &len));
        assert(len < BLKSIZ);
        ptxt += len;

        EVP_CIPHER_CTX_free(state);

        return ptxt - ptxt_start;
}

/* caller checks memory bounds */
static void decode_hdr(uint16_t *restrict a, uint16_t *restrict b, unsigned char *bytes) {
        memcpy(a, bytes, 2), memcpy(b, bytes+2, 2);
        *a = ntohs(*a), *b = ntohs(*b);
}

int parse_nts_fields(unsigned char (*base)[1280], size_t len, const struct NTS *nts, struct NTS_receipt *fields) {
        slice buf = { *base + 48, *base + len };
        int processed = 0;

        while(capacity(&buf) >= 4) {
                uint16_t type, len;
                decode_hdr(&type, &len, buf.data);
                check(capacity(&buf) >= len);

                switch(type) {
                        case UniqueIdentifier:
                                fields->identifier.data = buf.data + 4;
                                fields->identifier.length = len - 4;
                                ++processed;
                                break;
                        case AuthEncExtFields: {
                                uint16_t nonce_len, ciph_len;
                                decode_hdr(&nonce_len, &ciph_len, buf.data + 4);
                                check(nonce_len + ciph_len + 8 <= len);
                                unsigned char *nonce = buf.data + 8;
                                unsigned char *content = nonce + nonce_len;

                                slice info[] = {
                                        { *base, buf.data }, /* aad */
                                        { nonce, content },  /* nonce */
                                        { NULL },
                                };

                                int plain_len = read_encrypted_fields(content, content, ciph_len, info, nts);
                                check(plain_len < ciph_len);

                                slice plain = { content, content + plain_len };
                                while(capacity(&plain) >= 4) {
                                        uint16_t type, len;
                                        decode_hdr(&type, &len, plain.data);
                                        check(capacity(&plain) >= len);

                                        /* only care about cookies */
                                        switch(type) {
                                                case Cookie:
                                                        fields->new_cookie.data = plain.data + 4;
                                                        fields->new_cookie.length = len - 4;
                                                        ++processed;
                                                        break;
                                                default:
                                                        plain.data += len;
                                                        continue;
                                        }

                                        break;
                                }

                                break;
                        }

                        default:
                                /* ignore unknown fields */
                                ;
                };

                buf.data += len;
        }

        return processed;
}
