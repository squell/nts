#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <sys/socket.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/ssl.h>
#endif

#include "nts.h"
#include "nts_extfields.h"
#include "sntp.h"

uint8_t buffer[65536];

int NTS_attach_socket(const char *host, int port, int type);

int main(int argc, char **argv)
{
        const char *hostname = "ptbtime1.ptb.de";
        if (argc > 1) {
                hostname = argv[1];
        }
        int ntp_port = 123;
        int port = 4460;

        int sock = NTS_attach_socket(hostname, port, SOCK_STREAM);
        assert(sock > 0);

#ifdef USE_GNUTLS
        gnutls_session_t tls = NTS_TLS_setup(hostname, sock);
        assert(tls);

        assert(gnutls_handshake(tls) == 0);
        char *desc = gnutls_session_get_desc(tls);
        printf("GnuTLS: %s\n", desc);
        gnutls_free(desc);
#else
        SSL *tls = NTS_TLS_setup(hostname, sock);
	assert(SSL_connect(tls) == 1);
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

#ifdef USE_GNUTLS
        if (gnutls_record_send(tls, buffer, size) < size) {
#else
        size_t written;
        if (!SSL_write_ex(tls, buffer, size, &written)) {
#endif
                printf("failed to write request\n");
                goto end;
        }

        /*
         * Get up to sizeof(buf) bytes of the response. We keep reading until the
         * server closes the connection.
         */
        struct NTS_Query nts;

#ifdef USE_GNUTLS
        ssize_t readbytes;
retry:
        if ((readbytes = gnutls_record_recv(tls, buffer, sizeof(buffer))) > 0) {
#else
        size_t readbytes;
        if (SSL_read_ex(tls, buffer, sizeof(buffer), &readbytes)) {
#endif
                struct NTS_Agreement NTS;
                assert(NTS_decode_response(buffer, readbytes, &NTS) >= 0);
                if (NTS.error >= 0) {
                        printf("NTS error: 0x%04X\n", NTS.error);
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
                };

                assert(NTS_TLS_extract_keys(tls, NTS.aead_id, c2s, s2c, 64) == 0);
        } else {
#ifdef USE_GNUTLS
		if(!gnutls_error_is_fatal(readbytes)) goto retry;
#endif
                assert(!"could not read response");
        }

#ifdef USE_GNUTLS
        assert(gnutls_bye(tls, GNUTLS_SHUT_RDWR) == 0);
#else
        (void)(SSL_read_ex(tls, buffer, sizeof(buffer), &readbytes));
        assert(SSL_shutdown(tls) == 1);
#endif

        double delay, offset;
        nts_poll(hostname, ntp_port, &nts, &delay, &offset);
        printf("cookie*: ");
        for (size_t i=0; i < nts.cookie.length; i++)
                printf("%02x", nts.cookie.data[i]);
        printf("\n");
        printf("roundtrip delay: %f\n", delay);
        printf("offset: %f\n", offset);

        NTS_TLS_destroy(tls);
        return 0;
end:

        NTS_TLS_destroy(tls);
        return -1;
}
