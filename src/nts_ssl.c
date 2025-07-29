#include <threads.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "nts.h"

int NTS_SSL_extract_keys(
                SSL *ssl,
                NTS_AEADAlgorithmType aead,
                uint8_t *c2s,
                uint8_t *s2c,
                int key_capacity) {

        uint8_t *keys[] = { c2s, s2c };
        const char label[30] = { "EXPORTER-network-time-security" }; /* note: this does not include the zero byte */

        const struct NTS_AEADParam *info = NTS_GetParam(aead);
        if (!info)
                return -3;
        else if (info->key_size > key_capacity)
                return -2;

        for (int i=0; i < 2; i++) {
                const uint8_t context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
                if (1 != SSL_export_keying_material(
                                        ssl,
                                        keys[i], info->key_size,
                                        label, sizeof label,
                                        context, sizeof context, 1))
                        return -1;
        }

        return 0;
}

int NTS_attach_socket(const char *host, int port, int type);

static BIO* connect_bio(const char *hostname, int port, int blocking) {
        BIO *bio = BIO_new(BIO_s_socket());
        if (!bio) return NULL;

        int sock = NTS_attach_socket(hostname, port, SOCK_STREAM);
        if (sock < 0) return NULL;

        if (!blocking) {
                int flags;
                if ((flags = fcntl(sock, F_GETFL)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
                        return close(sock), NULL;
        }

        BIO_set_fd(bio, sock, BIO_CLOSE);
        return bio;
}

thread_local enum NTS_TLSErrorType NTS_SSL_error;

#define expect(expr) if (expr)

SSL* NTS_SSL_setup(const char *hostname, int port, int load_certs(SSL_CTX *), int blocking) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        expect(ctx); else {
                NTS_SSL_error = NTS_SSL_INTERNAL_ERROR;
                goto exit;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        (void) load_certs(ctx);

        expect(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);
        else {
                NTS_SSL_error = NTS_SSL_INTERNAL_ERROR;
                goto ctx_cleanup;
        }

        SSL *ssl = SSL_new(ctx);
        expect(ssl);
        else {
                NTS_SSL_error = NTS_SSL_INTERNAL_ERROR;
                goto ctx_cleanup;
        }

        BIO *bio = connect_bio(hostname, port, blocking);
        expect(bio);
        else {
                NTS_SSL_error = NTS_SSL_NO_CONNECTION;
                goto ssl_cleanup;
        }

        SSL_set_bio(ssl, bio, bio);

        unsigned char alpn[8] = "\x07ntske/1";
        expect(SSL_set_tlsext_host_name(ssl, hostname) == 1 &&
             SSL_set1_host(ssl, hostname) == 1 &&
             SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) == 0);
        else    {
                NTS_SSL_error = NTS_SSL_INTERNAL_ERROR;
                goto ssl_cleanup;
        }

        SSL_CTX_free(ctx);
        return ssl;

ssl_cleanup:
        SSL_free(ssl);
ctx_cleanup:
        SSL_CTX_free(ctx);
exit:
        return NULL;
}
