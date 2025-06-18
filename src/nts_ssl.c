#include "nts.h"

int NTS_SSL_extract_keys(SSL *ssl, NTS_AEAD_algorithm_type aead, unsigned char *c2s, unsigned char *s2c, int key_size) {
        unsigned char *keys[] = { c2s, s2c };
        const char label[30] = { "EXPORTER-network-time-security" }; /* note: this does not include the zero byte */

        if(NTS_aead_key_size(aead) != key_size) {
                return -2;
        }

        for(int i=0; i < 2; i++) {
                const unsigned char context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
                if(SSL_export_keying_material(ssl, keys[i], key_size, label, sizeof label, context, sizeof context, 1) != 1) {
                        return -1;
                }
        }

        return 0;
}
