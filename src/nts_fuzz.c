#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "nts.h"
#include "nts_crypto.h"
#include "nts_extfields.h"

void eat(volatile const uint8_t* buf, size_t size) {
        if (buf) while (size) (void)buf[size--];
}

/* this program does no sanity checking as it is meant for fuzzing only */
int main(int argc, char **argv) {
        int file = open(argv[1], O_RDONLY);
        assert(file >= 0);

        uint8_t buffer[1280];
        int len = read(file, buffer, 1280);
        if (len < 48) return 0;

        struct NTS_Query nts = (struct NTS_Query) {
                .cipher = *NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256),
                .c2s_key = (void*)"01234567890abcdef",
                .s2c_key = (void*)"01234567890abcdef",
        };

        if (argc > 2) {
                /* fuzz the nts ke */
                struct NTS_Agreement rec;
                if (NTS_decode_response(buffer, len, &rec) == 0) {
                        for (int i = 0; i < 8; i++)
                                eat(rec.cookie[i].data, rec.cookie[i].length);
                }
        } else {
                struct NTS_Receipt rcpt = { 0, };
                if (NTS_parse_extension_fields(buffer, len, &nts, &rcpt)) {
                        for (int i = 0; i < 8; i++)
                                eat(rcpt.new_cookie[i].data, rcpt.new_cookie[i].length);
                        eat(*rcpt.identifier, 32);
                }
        }

        return 0;
}
