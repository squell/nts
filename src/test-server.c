/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* This is a mock NTS server that is only used for integration tests.
 * Any error in the protocol quickly results in an assert, and it can
 * only communicate with a single client (hence why the NTS cookies 
 * do not matter)
 */

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nts.h"
#include "nts_crypto.h"
#include "nts_extfields.h"
#include "memory-util.h"

struct ntp_packet {
        uint8_t li_vn_mode;
        uint8_t stratum;
        uint8_t poll;
        uint8_t precision;
        uint32_t root_delay;
        uint32_t root_dispersion;
        char reference_id[4];
        uint64_t timestamp[4];
};

/* always pick this AEAD */
static const NTS_AEADAlgorithmType algo = NTS_AEAD_AES_SIV_CMAC_256;

/* always pick this NTP port */
static const uint16_t Port = 12345;

typedef uint8_t AEADKey[64];

static struct {
    AEADKey c2s, s2c;
} key;

static void serve_ntp_request(uint16_t port) //, AEADKey send_key, AEADKey recv_key)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sock > 0);

    struct sockaddr_in server = {}, client = {};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_aton("127.0.0.1", &server.sin_addr);

    assert(bind(sock, (struct sockaddr*)&server, sizeof(server)) == 0);

    struct ntp_packet packet;
    uint8_t buf[1280];

    socklen_t addrlen = sizeof(client);
    int len = recvfrom(sock, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&client, &addrlen);

    assert(len >= 48);

    const struct NTS_AEADParam *cipher = NTS_get_param(algo);
    assert(cipher);

    memcpy(&packet, buf, sizeof(packet));

    uint8_t unique_id[32];
    if (len > 48) {
        struct NTS_Query const query = {
            { (void*)"42", 2 },
            key.s2c, key.c2s,
            *cipher,
            0,
        };
        struct NTS_Receipt rcpt;
        assert(NTS_parse_extension_fields(buf, len, &query, &rcpt) > 0);
        /* getting "new cookies" from a client is an error */
        assert(rcpt.new_cookie->data == NULL);

        memcpy(unique_id, rcpt.identifier, 32);
    }

    /* simulate a SNTP reponse - you are always 42 seconds behind */
    uint64_t reply_time = be64toh(packet.timestamp[3]) + (42ULL<<32);

    packet.li_vn_mode = 044;
    packet.stratum = 16;
    packet.timestamp[0] = 0;
    packet.timestamp[1] = packet.timestamp[3];
    packet.timestamp[2] = packet.timestamp[3];
    packet.timestamp[3] = htobe64(reply_time);
    packet.timestamp[2] = htobe64(reply_time);

    if (len > 48) {
        int padding = 0;
        uint16_t payload[] = {
            htons(0x0204 /*Cookie*/), htons(8), htons(1), htons(1),
            htons(0x0204 /*Cookie*/), htons(8), htons(1), htons(2),
        };
        static_assert(sizeof(payload)%4 == 0, "payload must dword-padded");

        uint16_t id_field[] = {
            htons(0x0104 /*UniqId*/), htons(36),
               2, 4, 6, 8,10,12,14,16,18,20,22,24,26,28,30,32,
        };
        memcpy(id_field+2, unique_id, sizeof(unique_id));
        uint16_t auth_enc_field[] = {
            htons(0x0404 /*AE Fld*/), htons(8+cipher->nonce_size+cipher->block_size+sizeof(payload)+padding),
              htons(cipher->nonce_size),
              htons(cipher->block_size+sizeof(payload)),
        };

        zero(buf);
        uint8_t *p = buf;
        p = mempcpy(p, &packet, sizeof(packet));
        p = mempcpy(p, id_field, sizeof(id_field));
        p = mempcpy(p, auth_enc_field, sizeof(auth_enc_field));

        AssociatedData info[] = {
            { buf,  sizeof(packet) + sizeof(id_field) },
            { p,    cipher->nonce_size },
            {},
        };

        int ciphertext = NTS_encrypt(
            p + cipher->nonce_size, sizeof(buf) - (p - buf - cipher->nonce_size),
            (uint8_t*)payload, sizeof(payload),
            info,
            cipher, key.s2c
        );

        assert(ciphertext > 0);
        p += cipher->nonce_size + ciphertext + padding;

        sendto(sock, buf, p - buf, MSG_CONFIRM, (struct sockaddr*)&client, addrlen);
    } else {
        sendto(sock, &packet, sizeof(packet), MSG_CONFIRM, (struct sockaddr*)&client, addrlen);
    }

    close(sock);
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    (void) ssl;
    (void) arg;
    assert(SSL_select_next_proto((unsigned char**)out, outlen, (unsigned char*)"\x07ntske/1", 8, in, inlen) == OPENSSL_NPN_NEGOTIATED);
    return SSL_TLSEXT_ERR_OK;
}

static void wait_for_nts_ke(void)
{
    /* configure TLS */

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx);

    assert(SSL_CTX_use_certificate_chain_file(ctx, "server.crt") > 0);
    assert(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) > 0);

    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);

    SSL *tls = SSL_new(ctx);
    assert(tls);

    /* await the TCP connect */
    BIO *acceptor = BIO_new_accept("4460");
    assert(acceptor);
    assert(BIO_do_accept(acceptor) > 0);
    assert(BIO_do_accept(acceptor) > 0);
    BIO *bio = BIO_pop(acceptor);
    close(BIO_get_fd(acceptor, NULL));

    assert(bio);

    SSL_set_bio(tls, bio, bio);

    assert(SSL_accept(tls) > 0);

    /* read the NTS packet */
    struct NTS_Agreement NTS;
    size_t readbytes;
    uint8_t buf[1280];
    readbytes = SSL_read(tls, buf, sizeof(buf));
    assert(readbytes > 0);

    if (NTS_decode_response(buf, readbytes, &NTS) < 0) {
        printf("NTS error: %s (read %ld bytes)\n", NTS_error_string(NTS.error), readbytes);
        abort();
    }

    /* store the key */
    assert(NTS_TLS_extract_keys((void*)tls, algo, key.c2s, key.s2c, sizeof(AEADKey)) == 0);

    /* send a static reply */
    uint16_t reply[] = {
        htons(1/*NextProto*/),     htons(2), htons(0),
        htons(4/*AEADAlgorithm*/), htons(2), htons(algo),
        htons(7/*NTPv4Port*/),     htons(2), htons(12345),
        /* only send 2 cookies just to see what happens */
        htons(5/*NTPv4Cookie*/),   htons(4), htons(0), htons(1),
        htons(5/*NTPv4Cookie*/),   htons(4), htons(0), htons(2),
        htons(0/*EndOfMessage*/ | 0x8000),  htons(0),
    };

    SSL_write(tls, reply, sizeof(reply));
    SSL_free(tls);
    SSL_CTX_free(ctx);
}

int main(void)
{
    printf("KE: ");
    wait_for_nts_ke();
    puts("OK");

    printf("NTP: ");
    serve_ntp_request(Port);
    puts("OK");

    return 0;
}
