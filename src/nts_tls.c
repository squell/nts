#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <assert.h>

#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/ssl.h>
#endif

#include "nts.h"

int NTS_TLS_extract_keys(
                void *opaque,
                NTS_AEADAlgorithmType aead,
                uint8_t *c2s,
                uint8_t *s2c,
                int key_capacity) {

#ifdef USE_GNUTLS
        gnutls_session_t session = opaque;
#else
	SSL *session = opaque;
#endif

        uint8_t *keys[] = { c2s, s2c };
        const char label[30] = { "EXPORTER-network-time-security" }; /* note: this does not include the zero byte */

        const struct NTS_AEADParam *info = NTS_GetParam(aead);
        if (!info)
                return -3;
        else if (info->key_size > key_capacity)
                return -2;

        for (int i=0; i < 2; i++) {
                const char context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
#ifdef USE_GNUTLS
                if (gnutls_prf_rfc5705(
                                        session,
                                        sizeof(label), label,
                                        sizeof(context), context,
                                        info->key_size,
                                        (char *)keys[i]
                                ) != GNUTLS_E_SUCCESS)
#else
                if (SSL_export_keying_material(
                                        session,
                                        keys[i], info->key_size,
                                        label, sizeof label,
                                        (uint8_t *)context, sizeof context, 1)
                                != 1)
#endif
                        return -1;
        }

        return 0;
}

void NTS_TLS_destroy(void *opaque) {
#ifdef USE_GNUTLS
        gnutls_session_t session = opaque;

        void *certs = NULL;
        int r = gnutls_credentials_get(session, GNUTLS_CRD_CERTIFICATE, &certs);
        assert(r == GNUTLS_E_SUCCESS);

        int sock = gnutls_transport_get_int(session);
        gnutls_deinit(session);
        gnutls_certificate_free_credentials(certs);
        close(sock);
#else
        SSL_free(opaque);
#endif
}

#define CHECK(what) if(what); else goto CLEANUP;
#define CLEANUP exit

#ifdef USE_GNUTLS

void* NTS_TLS_setup(
                const char *hostname,
                int socket) {

        gnutls_certificate_credentials_t certs = NULL;
        gnutls_session_t tls = NULL;
        CHECK(gnutls_certificate_allocate_credentials(&certs) == GNUTLS_E_SUCCESS);
        #undef CLEANUP
        #define CLEANUP ctx_cleanup

        CHECK(gnutls_init(&tls, GNUTLS_CLIENT) == GNUTLS_E_SUCCESS);
        #undef CLEANUP
        #define CLEANUP sess_cleanup

        CHECK(gnutls_certificate_set_x509_system_trust(certs) > 0);
        CHECK(gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, certs) == GNUTLS_E_SUCCESS);

        CHECK(gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL) == GNUTLS_E_SUCCESS);
        gnutls_session_set_verify_cert(tls, hostname, 0);

        CHECK(gnutls_server_name_set(tls, GNUTLS_NAME_DNS, hostname, strlen(hostname)) == GNUTLS_E_SUCCESS);

        unsigned char alpn[7] = "ntske/1";
        CHECK(
                gnutls_alpn_set_protocols(
                        tls,
                        &(gnutls_datum_t){ .data = alpn, .size = sizeof(alpn) },
                        1,
                        GNUTLS_ALPN_MANDATORY
                ) == GNUTLS_E_SUCCESS
        );

        gnutls_transport_set_int(tls, socket);
        gnutls_handshake_set_timeout(tls, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        return tls;

sess_cleanup:
        gnutls_deinit(tls);
ctx_cleanup:
        gnutls_certificate_free_credentials(certs);
exit:
        return NULL;
}
#undef CLEANUP

#else

void* NTS_TLS_setup(
                const char *hostname,
                int socket) {

        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        CHECK(ctx);
        #undef CLEANUP
        #define CLEANUP ctx_cleanup

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        CHECK(SSL_CTX_set_default_verify_paths(ctx) == 1);
        CHECK(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);

        SSL *tls = SSL_new(ctx);
        CHECK(tls);
        #undef CLEANUP
        #define CLEANUP sess_cleanup

        CHECK(SSL_set1_host(tls, hostname) == 1);
        CHECK(SSL_set_tlsext_host_name(tls, hostname) == 1);

        unsigned char alpn[8] = "\x07ntske/1";
        CHECK(SSL_set_alpn_protos(tls, alpn, sizeof(alpn)) == 0);

        BIO *bio = BIO_new(BIO_s_socket());
        CHECK(bio);
        BIO_set_fd(bio, socket, BIO_CLOSE);
	SSL_set_bio(tls, bio, bio);

        SSL_CTX_free(ctx);
        return tls;

sess_cleanup:
        SSL_free(tls);
ctx_cleanup:
        SSL_CTX_free(ctx);
exit:
        return NULL;
}
#endif
