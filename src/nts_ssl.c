#include <threads.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "nts.h"

int NTS_SSL_extract_keys(SSL *ssl, NTS_AEAD_algorithm_type aead, unsigned char *c2s, unsigned char *s2c, int key_capacity) {
	unsigned char *keys[] = { c2s, s2c };
	const char label[30] = { "EXPORTER-network-time-security" }; /* note: this does not include the zero byte */

	int key_size = NTS_AEAD_key_size(aead);
	if(!key_size) {
		return -3;
	} else if(key_size > key_capacity) {
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

#ifndef USE_LIBAES_SIV
EVP_CIPHER *NTS_AEAD_cipher(NTS_AEAD_algorithm_type id) {
	const char *name = NTS_AEAD_cipher_name(id);
	return name? EVP_CIPHER_fetch(NULL, name, NULL) : NULL;
}
#endif

int NTS_attach_socket(const char *host, int port, int type);

static BIO *connect_bio(const char *hostname, int port, int blocking) {
	BIO *bio = BIO_new(BIO_s_socket());
	if(!bio) return NULL;

	int sock = NTS_attach_socket(hostname, port, SOCK_STREAM);
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

thread_local enum NTS_SSL_error_type NTS_SSL_error;

#define expect(expr) if(expr)

SSL *NTS_SSL_setup(const char *hostname, int port, int load_certs(SSL_CTX *), int blocking) {
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
