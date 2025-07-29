#include <sys/types.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>

#include "nts_extfields.h"
#include "nts_crypto.h"

#if defined(OPENSSL_WORKAROUND) && OPENSSL_VERSION_PREREQ(3,5)
#  warning The OpenSSL workaround is not necessary.
#endif

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

typedef struct {
        uint8_t *data;
        uint8_t *data_end;
} slice;

static size_t capacity(const slice *slice) {
        return slice->data_end - slice->data;
}

static int write_ntp_ext_field(slice *buf, uint16_t type, void *contents, uint16_t len, uint16_t size) {
        /* enforce minimum size */
        if (size < len+4) size = len+4;
        /* pad to a dword boundary */
        uint16_t padded_len = (size+3) & ~3;
        int padding = padded_len - (len+4);

        if (capacity(buf) < padded_len)
                return 0;

        memmove(buf->data+4, contents, len);
        type = htobe16(type);
        memcpy(buf->data, &type, 2);
        len = htobe16(padded_len);
        memcpy(buf->data+2, &len, 2);

        buf->data += padded_len;
        memset(buf->data - padding, 0, padding);
        return padded_len;
}

enum extfields {
        UniqueIdentifier = 0x0104,
        Cookie           = 0x0204,
        AuthEncExtFields = 0x0404,
        NoOpField        = 0x0200,
};

#define check(expr) if (expr); else goto exit;

int NTS_add_extension_fields(
                uint8_t (*dest)[1280],
                const struct NTS_Query *nts,
                uint8_t (*uniq_id)[32]) {

        slice buf = { *dest, *dest + 1280 };

        /* skip beyond regular ntp portion */
        buf.data += 48;

        /* generate unique identifier */
        uint8_t rand_buf[32], *rand = *(uniq_id? uniq_id : &rand_buf);
        getrandom(rand, sizeof(rand_buf), 0);
        check(write_ntp_ext_field(&buf, UniqueIdentifier, rand, sizeof(rand_buf), 16));

        /* write cookie field */
        check(write_ntp_ext_field(&buf, Cookie, nts->cookie.data, nts->cookie.length, 16));

        /* --- cobble together the extension fields extension field --- */

        /* this represents "N_REQ" in the RFC */
        uint8_t const req_nonce_len = nts->cipher.nonce_size;
        uint8_t const nonce_len = req_nonce_len;
        uint8_t EF[64] = { 0, nonce_len, 0, 0, }; /* 64 bytes are plenty */
        assert((nonce_len & 3) == 0);
        assert((req_nonce_len & 3) == 0 && req_nonce_len <= 16);

#ifdef OPENSSL_WORKAROUND
        /* bug in OpenSSL: https://github.com/openssl/openssl/issues/26580,
           which means that a ciphertext HAS TO BE PRESENT */
        uint8_t plain_text[4];
        slice ptxt = { plain_text, plain_text+sizeof(plain_text) };
        int ptxt_len = write_ntp_ext_field(&ptxt, NoOpField, plain_text, 0, 0);
#else
        /* a dummy pointer -- it has to be non-NULL, but it will not be read from */
        uint8_t *const plain_text = buf.data;
        int ptxt_len = 0;
#endif

        /* generate the nonce */
        getrandom(EF+4, nonce_len, 0);
        uint8_t *EF_payload = EF+4+nonce_len;

        AssociatedData info[] = {
                { *dest, buf.data - *dest },  /* aad */
                { EF+4,  nonce_len },         /* nonce */
                { NULL },
        };

        assert((int)sizeof(EF) - (EF_payload - EF) >= ptxt_len + nts->cipher.block_size);

        int ctxt_len = NTS_encrypt(EF_payload, plain_text, ptxt_len, info, &nts->cipher, nts->c2s_key);
        check(ctxt_len >= 0);

        /* add padding if we used a too-short nonce */
        int ef_len = 4 + ctxt_len + nonce_len + (nonce_len < req_nonce_len)*(req_nonce_len - nonce_len);

        /* set the ciphertext length */
        ctxt_len = htobe16(ctxt_len);
        memcpy(EF+2, &ctxt_len, 2);

        check(write_ntp_ext_field(&buf, AuthEncExtFields, EF, ef_len, 28));

        return buf.data - *dest;
exit:
        return 0;
}

/* caller checks memory bounds */
static void decode_hdr(uint16_t *restrict a, uint16_t *restrict b, uint8_t *bytes) {
        memcpy(a, bytes, 2), memcpy(b, bytes+2, 2);
        *a = be16toh(*a), *b = be16toh(*b);
}

int NTS_parse_extension_fields(
                uint8_t (*src)[1280],
                size_t src_len,
                const struct NTS_Query *nts,
                struct NTS_Receipt *fields) {

        assert(src_len >= 48 && src_len <= sizeof(*src));
        slice buf = { *src + 48, *src + src_len };
        int processed = 0;

        while (capacity(&buf) >= 4) {
                uint16_t type, len;
                decode_hdr(&type, &len, buf.data);
                check(len >= 4);
                check(capacity(&buf) >= len);

                switch (type) {
                case UniqueIdentifier:
                        check(len - 4 == 32);
                        fields->identifier = (uint8_t (*)[32])(buf.data + 4);
                        ++processed;
                        break;
                case AuthEncExtFields: {
                        uint16_t nonce_len, ciph_len;
                        decode_hdr(&nonce_len, &ciph_len, buf.data + 4);
                        check(nonce_len + ciph_len + 8 <= len);
                        uint8_t *nonce = buf.data + 8;
                        uint8_t *content = nonce + nonce_len;

                        AssociatedData info[] = {
                                { *src, buf.data - *src }, /* aad */
                                { nonce, nonce_len },      /* nonce */
                                { NULL },
                        };

                        uint8_t *plaintext = content;
                        int plain_len = NTS_decrypt(plaintext, content, ciph_len, info, &nts->cipher, nts->s2c_key);
                        assert(plain_len < ciph_len);
                        check(plain_len >= 0);

                        slice plain = { plaintext, plaintext + plain_len };

                        while (capacity(&plain) >= 4) {
                                uint16_t type, len;
                                decode_hdr(&type, &len, plain.data);
                                check(capacity(&plain) >= len);
                                check(len >= 4);

                                /* only care about cookies */
                                switch (type) {
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
                }

                buf.data += len;
        }

exit:
        return 0;
}
