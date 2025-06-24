#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "nts.h"
#include "nts_extfields.h"

/* this program does no sanity checking as it is meant for fuzzing only */

int main(int argc, char **argv) {
        int file = open(argv[1], O_RDONLY);
        unsigned char buffer[1280];
        int len = read(file, buffer, 1280);
        if(len < 48) return 0;
        int aead_id = NTS_AEAD_AES_SIV_CMAC_256;

        struct NTS nts = (struct NTS) {
#ifndef USE_LIBAES_SIV
                .cipher = NTS_AEAD_cipher(aead_id),
#else
                .key_len = NTS_AEAD_key_size(aead_id),
#endif
                .c2s_key = (void*)"01234567890abcdef",
                .s2c_key = (void*)"01234567890abcdef",
        };

        if(argc > 2) {
                /* fuzz the nts ke */
                struct NTS_response rec;
                (void) NTS_decode_response(buffer, len, &rec);
        } else {
                struct NTS_receipt rcpt = { 0, };
                (void) parse_nts_fields(&buffer, len, &nts, &rcpt);
        }

        return 0;
}

/* make sure encryption is a no-op --- currently only when LIBAES_SIV is used */

#define STUB(name) int name() { return 1; }

#ifndef USE_LIBAES_SIV
#  error can only fuzz when configured for libaes_siv, currently
#else
/* stub libaes_siv functions */
STUB(AES_SIV_Init)
STUB(AES_SIV_AssociateData)
STUB(AES_SIV_EncryptFinal)
STUB(AES_SIV_DecryptFinal)
STUB(AES_SIV_CTX_free)
void *AES_SIV_CTX_new() { return ""; }
#endif
