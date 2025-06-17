/*
 *  Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

/*
 * NB: Changes to this file should also be reflected in
 * doc/man7/ossl-guide-tls-client-block.pod
 */

#include <string.h>

/* Include the appropriate header file for SOCK_STREAM */
#ifdef _WIN32 /* Windows */
# include <winsock2.h>
#else /* Linux/Unix */
# include <sys/socket.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "nts.h"

/* Helper function to create a BIO connected to the server */
static BIO *create_socket_bio(const char *hostname, const char *port, int family)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    /*
     * Lookup IP address info for the server.
     */
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_STREAM, 0,
                       &res))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        /*
         * Create a TCP socket. We could equally use non-OpenSSL calls such
         * as "socket" here for this and the subsequent connect and close
         * functions. But for portability reasons and also so that we get
         * errors on the OpenSSL stack in the event of a failure we use
         * OpenSSL's versions of these functions.
         */
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* We have a connected socket so break out of the loop */
        break;
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(res);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket */
    bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }

    /*
     * Associate the newly created BIO with the underlying socket. By
     * passing BIO_CLOSE here the socket will be automatically closed when
     * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which
     * case you must close the socket explicitly when it is no longer
     * needed.
     */
    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
}

unsigned char buffer[65536];

/*
 * adapted from openssl demo
 */
int main(int argc, char **argv)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    int res = EXIT_FAILURE;
    int ret;
    size_t written, readbytes;
    char *hostname, *port;

    hostname = "ptbtime1.ptb.de";
    if(argc > 1) {
	hostname = argv[1];
    }
    port = "4460";

    /*
     * Create an SSL_CTX which we can use to create SSL objects from. We
     * want an SSL_CTX for creating clients so we use TLS_client_method()
     * here.
     */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
	    printf("Failed to create the SSL_CTX\n");
	    goto end;
    }

    /*
     * Configure the client to abort the handshake if certificate
     * verification fails. Virtually all clients should do this unless you
     * really know what you are doing.
     */
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Use the default trusted certificate store */
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        printf("Failed to set the default trusted certificate store\n");
        goto end;
    }

    /* We require a minimum TLS version of TLSv1.3.
     */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
        goto end;
    }

    /* Create an SSL object to represent the TLS connection */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to create the SSL object\n");
        goto end;
    }

    /*
     * Create the underlying transport socket/BIO and associate it with the
     * connection.
     */
    bio = create_socket_bio(hostname, port, AF_INET);
    if (bio == NULL) {
        printf("Failed to create the BIO\n");
        goto end;
    }
    SSL_set_bio(ssl, bio, bio);

    /*
     * Tell the server during the handshake which hostname we are attempting
     * to connect to in case the server supports multiple hosts.
     */
    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        printf("Failed to set the SNI hostname\n");
        goto end;
    }

    /*
     * Ensure we check during certificate verification that the server has
     * supplied a certificate for the hostname that we were expecting.
     * Virtually all clients should do this unless you really know what you
     * are doing.
     */
    if (!SSL_set1_host(ssl, hostname)) {
        printf("Failed to set the certificate verification hostname");
        goto end;
    }

    /* Set the ALPN to NTS */
    unsigned char alpn[8] = "\x07ntske/1";
    if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0) {
        printf("Failed to set the ALPN for the connection.");
        goto end;
    }
    /* Do the handshake with the server */
    if (SSL_connect(ssl) < 1) {
        printf("Failed to connect to the server\n");
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            printf("Verify error: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        goto end;
    }

    /* Write a NTS request */
    int size = NTS_encode_request(buffer, sizeof(buffer), NULL);

    if (!SSL_write_ex(ssl, buffer, size, &written)) {
	printf("Failed to write request\n");
	goto end;
    }

    /*
     * Get up to sizeof(buf) bytes of the response. We keep reading until the
     * server closes the connection.
     */
    while (SSL_read_ex(ssl, buffer, sizeof(buffer), &readbytes)) {
	struct NTS_response NTS;
	NTS_decode_response(buffer, readbytes, &NTS);
	printf("> CODE: %d\n", NTS.result);
	printf("> AEAD %d\n", NTS.aead_id);
	printf("> %s:%d\n", NTS.ntp_server? NTS.ntp_server : "*", NTS.ntp_port);
	for(int i=0; NTS.cookie[i].data; i++) {
		printf("| ");
		for(size_t n=0; n < NTS.cookie[i].length; n++)
			printf("%02x", NTS.cookie[i].data[n]);
		printf("\n");
	}
    }

    /* In case the response didn't finish with a newline we add one now */
    printf("\n");

    /*
     * Check whether we finished the while loop above normally or as the
     * result of an error. The 0 argument to SSL_get_error() is the return
     * code we received from the SSL_read_ex() call. It must be 0 in order
     * to get here. Normal completion is indicated by SSL_ERROR_ZERO_RETURN.
     */
    if (SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        /*
         * Some error occurred other than a graceful close down by the
         * peer.
         */
        printf ("Failed reading remaining data\n");
        goto end;
    }

    /*
     * The peer already shutdown gracefully (we know this because of the
     * SSL_ERROR_ZERO_RETURN above). We should do the same back.
     */
    ret = SSL_shutdown(ssl);
    if (ret < 1) {
        /*
         * ret < 0 indicates an error. ret == 0 would be unexpected here
         * because that means "we've sent a close_notify and we're waiting
         * for one back". But we already know we got one from the peer
         * because of the SSL_ERROR_ZERO_RETURN above.
         */
        printf("Error shutting down\n");
        goto end;
    }

    /* Success! */
    res = EXIT_SUCCESS;
 end:
    /*
     * If something bad happened then we will dump the contents of the
     * OpenSSL error stack to stderr. There might be some useful diagnostic
     * information there.
     */
    if (res == EXIT_FAILURE)
        ERR_print_errors_fp(stderr);

    /*
     * Free the resources we allocated. We do not free the BIO object here
     * because ownership of it was immediately transferred to the SSL object
     * via SSL_set_bio(). The BIO will be freed when we free the SSL object.
     */
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return res;
}
