#include <threads.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

int nts_attach_socket(const char *host, int port, int type);

static BIO *connect_bio(const char *hostname, int port, int blocking) {
	BIO *bio = BIO_new(BIO_s_socket());
	if(!bio) return NULL;

	int sock = nts_attach_socket(hostname, port, SOCK_STREAM);
	if(sock < 0) return NULL;
	if(!blocking) {
		int flags;
		if((flags = fcntl(sock, F_GETFL)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
			return close(sock), NULL;
		}
	}

	BIO_set_fd(bio, sock, BIO_CLOSE);
	return bio;
}

thread_local enum {
	NTS_SSL_INTERNAL_ERROR,
	NTS_SSL_NO_CONNECTION,
} NTS_SSL_error;

#define expect if

SSL *nts_setup_ssl(const char *hostname, int port, int load_certs(SSL_CTX *), int blocking) {
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	expect(ctx); else {
		NTS_SSL_error = NTS_SSL_INTERNAL_ERROR;
		goto exit;
	}

	if(strcmp(hostname, "localhost") == 0) {
		/* circumvent certificate checking for easy testing */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	}

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

#undef expect
