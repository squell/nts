#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "nts.h"
#include "nts_extfields.h"

/* it's the callers job to ensure bounds are not transgressed */
#define encode_record_raw(msg, type, data, len) encode_ptr_len_data(msg, type, data, len, 0)
#define encode_record_raw_ext(msg, type, data, len) encode_ptr_len_data(msg, type, data, len, 1)

static void encode_ptr_len_data(unsigned char **message, uint16_t type, const void *data, uint16_t len, int count_hdr) {
        unsigned char hdr[4] = {
                type >> 8,
                type & 0xFF,
                (len + count_hdr*sizeof(hdr)) >> 8,
                (len + count_hdr*sizeof(hdr)) & 0xFF,
        };

        memcpy(*message, hdr, 4);
        if(len) memcpy(*message+4, data, len);
        *message += len + 4;
}

void test_nts_encoding(void) {
        unsigned char buffer[1000];
        struct NTS_agreement rec;

        NTS_encode_request(buffer, sizeof buffer, NULL);
        assert(NTS_decode_response(buffer, 1000, &rec) == 0);
        assert(rec.error == NTS_SUCCESS);
        assert(rec.ntp_server == NULL);
        assert(rec.ntp_port == 0);
        assert(rec.cookie[0].data == NULL);
        assert(rec.cookie[0].length == 0);
        assert(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_256);

        uint16_t proto1[] = { NTS_AEAD_AES_SIV_CMAC_256, NTS_AEAD_AES_SIV_CMAC_512, 0 };
        NTS_encode_request(buffer, sizeof buffer, proto1);
        assert(NTS_decode_response(buffer, 1000, &rec) == 0);
        assert(rec.error == NTS_SUCCESS);
        assert(rec.ntp_server == NULL);
        assert(rec.ntp_port == 0);
        assert(rec.cookie[0].data == NULL);
        assert(rec.cookie[0].length == 0);
        assert(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_256);

        uint16_t proto2[] = { NTS_AEAD_AES_SIV_CMAC_512, NTS_AEAD_AES_SIV_CMAC_256, 0 };
        NTS_encode_request(buffer, sizeof buffer, proto2);
        assert(NTS_decode_response(buffer, 1000, &rec) == 0);
        assert(rec.error == NTS_SUCCESS);
        assert(rec.ntp_server == NULL);
        assert(rec.ntp_port == 0);
        assert(rec.cookie[0].data == NULL);
        assert(rec.cookie[0].length == 0);
        assert(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_512);
}

void test_nts_decoding(void) {
        unsigned char buffer[0x10000], *p;
        struct NTS_agreement rec;

        /* empty */
        uint8_t value[2] = { 0, };
        encode_record_raw((p = buffer, &p), 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_BAD_RESPONSE);

        /* missing aead */
        encode_record_raw((p = buffer, &p), 1, &value, 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_BAD_RESPONSE);

        /* missing nextproto */
        encode_record_raw((p = buffer, &p), 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_BAD_RESPONSE);

        /* invalid nextproto */
        encode_record_raw((p = buffer, &p), 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 1, (value[1] = 3, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_NO_PROTOCOL);

        /* invalid aead */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 37, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_NO_AEAD);

        /* unknown critical record */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 0xfe | 0x8000, &value, 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_BAD_RESPONSE);

        /* error record */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 2, (value[1] = 42, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == 42);

        /* warning record */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 3, (value[1] = 42, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert(rec.error == NTS_UNEXPECTED_WARNING);

        /* valid */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 5, "COOKIE1", 7);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 5, "COOKIE22", 8);
        encode_record_raw(&p, 0xee, "unknown", 7);
        encode_record_raw(&p, 7, (value[1] = 42, &value), 2);
        encode_record_raw(&p, 5, "COOKIE333", 9);
        encode_record_raw(&p, 6, "localhost", 9);
        encode_record_raw(&p, 5, "COOKIE4444", 10);
        assert(NTS_decode_response(buffer, sizeof buffer, &rec) == 0);
        assert(rec.error == NTS_SUCCESS);
        assert(rec.aead_id == 15);
        assert(rec.ntp_port == 42);
        assert(strcmp(rec.ntp_server, "localhost") == 0);
        assert(memcmp(rec.cookie[0].data, "COOKIE1", rec.cookie[0].length) == 0);
        assert(memcmp(rec.cookie[1].data, "COOKIE22", rec.cookie[1].length) == 0);
        assert(memcmp(rec.cookie[2].data, "COOKIE333", rec.cookie[2].length) == 0);
        assert(memcmp(rec.cookie[3].data, "COOKIE4444", rec.cookie[3].length) == 0);
        assert(rec.cookie[4].data == NULL);
        assert(rec.cookie[4].length == 0);
}

void test_ntp_field_encoding(void) {
        unsigned char buffer[1280];

        char cookie[] = "PAD";

        struct NTS_query nts = {
                { (uint8_t*)cookie, strlen(cookie) },
                (uint8_t*)"0123456789abcdef",
                (uint8_t*)"0123456789abcdef",
#ifndef USE_LIBAES_SIV
                EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL),
#else
                32,
#endif
        };

        struct NTS_receipt rcpt = { 0, };
        int len = NTS_add_extension_fields(&buffer, &nts, NULL);
        assert(len > 48);
        assert(NTS_parse_extension_fields(&buffer, len, &nts, &rcpt));

        assert(rcpt.new_cookie.data == NULL);
        assert(memcmp(buffer + 48 + 36 + 4, cookie, strlen(cookie)) == 0);
        assert(strcmp((char*)buffer + 48 + 36 + 4, cookie) == 0);

        memset(&rcpt, 0, sizeof(rcpt));
        len = NTS_add_extension_fields(&buffer, &nts, NULL);
        buffer[0]++;
        assert(!NTS_parse_extension_fields(&buffer, len, &nts, &rcpt));

        memset(&rcpt, 0, sizeof(rcpt));
        len = NTS_add_extension_fields(&buffer, &nts, NULL);
        nts.s2c_key = (uint8_t*)"000000000000000";
        assert(!NTS_parse_extension_fields(&buffer, len, &nts, &rcpt));
}

void add_encrypted_server_hdr(unsigned char *buffer, unsigned char **p_ptr, struct NTS_query nts, const char *cookie, unsigned char *corrupt) {
        unsigned char *af = *p_ptr;
        unsigned char *pt;
        /* write nonce */
        *p_ptr = pt = (unsigned char*)mempcpy(af+8, "123NONCE", 8) + 16;
        /* write fields */
        encode_record_raw_ext(p_ptr, 0x0104, "A sharp mind cuts through deceit", 32);
        encode_record_raw_ext(p_ptr, 0x0204, cookie, strlen(cookie));

        /* corrupt a byte */
        if(corrupt) *corrupt = 0xee;

        /* encrypt fields */
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int ignore;
        EVP_EncryptInit_ex(ctx, cipher, NULL, nts.s2c_key, NULL);
        EVP_EncryptUpdate(ctx, NULL, &ignore, buffer, af - buffer);
        EVP_EncryptUpdate(ctx, NULL, &ignore, (uint8_t*)"123NONCE", 8);
        EVP_EncryptUpdate(ctx, pt, &ignore, pt, *p_ptr - pt);
        EVP_EncryptFinal_ex(ctx, buffer, &ignore);
        assert(ignore == 0);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, pt - 16);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);

        /* set type to 0x404 */
        memset(af, 0, 8);
        af[0] = af[1] = 0x04;
        /* set overall packet length */
        af[3] = *p_ptr - af;
        /* set nonce length */
        af[5] = 8;
        /* set ciphertext length */
        af[7] = *p_ptr - pt + 16;
}

static void test_ntp_field_decoding(void) {
        unsigned char buffer[1280];

        char cookie[] = "COOKIE";

        struct NTS_query nts = {
                { (uint8_t*)cookie, strlen(cookie) },
                (uint8_t*)"0123456789abcdef",
                (uint8_t*)"0123456789abcdef",
#ifndef USE_LIBAES_SIV
                EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL),
#else
                32,
#endif
        };

        unsigned char *p =  buffer + 48;

	char ident[32] = "Silence speaks louder than words";

        /* this deliberately breaks padding rules and sneaks an encrypted identifier */
        encode_record_raw_ext(&p, 0x0104, ident, 32);
        add_encrypted_server_hdr(buffer, &p, nts, cookie, NULL);

        struct NTS_receipt rcpt = { 0, };
        assert(NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        assert(memcmp(rcpt.identifier, ident, 32) == 0);
        assert(rcpt.new_cookie.data != NULL);
        assert(rcpt.new_cookie.length >= strlen(cookie));
        assert(memcmp(rcpt.new_cookie.data, cookie, strlen(cookie)) == 0);

        /* same test but no authentication of uniq id */
        p = buffer + 48;
        add_encrypted_server_hdr(buffer, &p, nts, cookie, NULL);
        encode_record_raw_ext(&p, 0x0104, ident, 32);

        memset(&rcpt, 0, sizeof(rcpt));
        assert(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        /* no authentication at all */
        p = buffer + 48;
        encode_record_raw(&p, 0x0104, ident, 32);
        memset(&rcpt, 0, sizeof(rcpt));
        assert(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        /* malicious unencrypted field */
        p = buffer + 48;
        encode_record_raw_ext(&p, 0x0104, ident, 32);
        add_encrypted_server_hdr(buffer, &p, nts, cookie, NULL);
        buffer[48+2] = 0xee;
        memset(&rcpt, 0, sizeof(rcpt));
        assert(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        /* malicious encrypted field */
        p = buffer + 48;
        encode_record_raw_ext(&p, 0x0104, ident, 32);
        /* at p+32 the first plaintext data will be written
         * so at p+34 is the MSB of the first field length */
        add_encrypted_server_hdr(buffer, &p, nts, cookie, p+34);

        memset(&rcpt, 0, sizeof(rcpt));
        assert(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));
}

int main(void) {
        test_nts_encoding();
        test_nts_decoding();
        test_ntp_field_encoding();
        test_ntp_field_decoding();
        assert(NTS_AEAD_key_size(NTS_AEAD_AES_SIV_CMAC_256) == 32);
        assert(NTS_AEAD_key_size(NTS_AEAD_AES_SIV_CMAC_384) == 48);
        assert(NTS_AEAD_key_size(NTS_AEAD_AES_SIV_CMAC_512) == 64);

        return 0;
}
