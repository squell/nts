#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <sys/socket.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#endif

#include "nts.h"
#include "nts_extfields.h"
#include "sntp.h"

uint8_t buffer[65536];

int NTS_attach_socket(const char *host, int port, int type);

int main(int argc, char **argv)
{
        const char *hostname = "time.tweede.golf";
        if (argc > 1) {
                hostname = argv[1];
        }
        int ntp_port = 123;
        int port = 4460;

        int sock = NTS_attach_socket(hostname, port, SOCK_STREAM);
        assert(sock > 0);

        NTS_TLS *tls = NTS_TLS_setup(hostname, sock);
        assert(tls);

        assert(NTS_TLS_handshake(tls) == 0);

#ifdef USE_GNUTLS
        char *desc = gnutls_session_get_desc((gnutls_session_t)tls);
        printf("GnuTLS: %s\n", desc);
        gnutls_free(desc);
#endif

        uint16_t pref_arr[4] = { 0, }, *prefs = NULL;
        if (argc > 5) {
                printf("too many AEAD's specified\n");
                goto end;
        } else if (argc > 2) {
                prefs = pref_arr;
                for (char **arg = argv+2; *arg; arg++) {
                        #define parse(type) if (strstr(#type, *arg)) \
                                (void) (NTS_GetParam(*prefs++ = NTS_##type) || printf("warning: AEAD %s is not supported by this build\n", #type))
                        if (strnlen(*arg, 3) < 3) continue; else
                        parse(AEAD_AES_SIV_CMAC_256); else
                        parse(AEAD_AES_SIV_CMAC_384); else
                        parse(AEAD_AES_SIV_CMAC_512); else
                        parse(AEAD_AES_128_GCM_SIV); else
                        parse(AEAD_AES_256_GCM_SIV); else {
                                printf("unknown AEAD: %s\n", *arg);
                                goto end;
                        }
                        #undef parse
                }
                prefs = pref_arr;
        }

        int size = NTS_encode_request(buffer, sizeof(buffer), prefs);

        if (NTS_TLS_write(tls, buffer, size) < size) {
                printf("failed to write request\n");
                goto end;
        }

        /*
         * Get up to sizeof(buf) bytes of the response. We keep reading until the
         * server closes the connection.
         */
        struct NTS_Query nts;
        size_t readbytes;

        uint8_t *bufp = buffer;
retry:
        if ((readbytes = NTS_TLS_read(tls, bufp, sizeof(buffer) - (bufp - buffer))) > 0) {
                struct NTS_Agreement NTS;
                bufp += readbytes;
                if (NTS_decode_response(buffer, bufp - buffer, &NTS) < 0) {
                        printf("NTS error: %s (read: %ld bytes)\n", NTS_error_string(NTS.error), readbytes);
                        if (NTS.error == NTS_INSUFFICIENT_DATA) {
                                goto retry;
                        }
                        goto end;
                }

                assert(NTS_GetParam(NTS.aead_id));
                printf("selected AEAD: %s\n", NTS_GetParam(NTS.aead_id)->cipher_name);

                #define FALLBACK(x, y) (x? x : y)
                hostname = FALLBACK(NTS.ntp_server, hostname);
                ntp_port = FALLBACK(NTS.ntp_port, ntp_port);

                printf("ntp server: %s:%d\n", hostname, ntp_port);
                for (int i=0; i < 8; i++) {
                        printf("cookie%d: ", i+1);
                        if (NTS.cookie[i].data) {
                                for (size_t n=0; n < NTS.cookie[i].length; n++)
                                                printf("%02x", NTS.cookie[i].data[n]);
                        } else {
                                printf("<absent>");
                        }
                        printf("\n");
                }

                static uint8_t c2s[64], s2c[64];
                nts = (struct NTS_Query) {
                        .cipher = *NTS_GetParam(NTS.aead_id),
                        .c2s_key = c2s,
                        .s2c_key = s2c,
                        .cookie = *NTS.cookie,
                        .extra_cookies = 2,
                };

                assert(NTS_TLS_extract_keys(tls, NTS.aead_id, c2s, s2c, 64) == 0);
        } else {
                if (readbytes == 0) goto retry;
                assert(!"could not read response");
        }

        NTS_TLS_close(tls);

        double delay, offset;
        int count;
        nts_poll(hostname, ntp_port, &nts, &delay, &offset, &count);
        printf("cookie*: ");
        for (size_t i=0; i < nts.cookie.length; i++)
                printf("%02x", nts.cookie.data[i]);
        printf("\n");
        assert(count <= nts.extra_cookies+1);
        printf("fresh cookies: %d%s\n", count, (count<nts.extra_cookies+1)? " (LESS THAN REQUESTED)" : "");
        printf("roundtrip delay: %f\n", delay);
        printf("offset: %f\n", offset);

        return 0;
end:

        NTS_TLS_close(tls);
        return -1;
}
