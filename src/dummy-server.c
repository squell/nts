#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>

#include "nts.h"
#include "nts_extfields.h"

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

static const NTS_AEADAlgorithmType algo = NTS_AEAD_AES_SIV_CMAC_256;

typedef uint8_t AEADKey[32];

static struct {
    AEADKey c2s, s2c;
} key;

static void serve_ntp_request(uint16_t port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sock > 0);

    struct sockaddr_in server = { 0, }, client = { 0, };
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);

    assert(bind(sock, (struct sockaddr*)&server, sizeof(server)) == 0);

    struct ntp_packet packet;
    uint8_t buf[1280];

    socklen_t addrlen = sizeof(client);
    int len = recvfrom(sock, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&client, &addrlen);

    assert(len >= 48);

    const struct NTS_AEADParam *param = NTS_get_param(algo);
    assert(param);

    memcpy(&packet, buf, sizeof(packet));

    uint8_t unique_id[32];
    if (len > 48) {
        struct NTS_Query const query = {
            { (void*)"42", 2 },
            key.s2c, key.c2s,
            *param,
            0,
        };
        struct NTS_Receipt rcpt;
        assert(NTS_parse_extension_fields(&buf, len, &query, &rcpt) > 0);
        /* getting "new cookies" from a client is an error */
        assert(rcpt.new_cookie->data == NULL);

        memcpy(unique_id, rcpt.identifier, 32);
    }

    /* simulate a SNTP reponse - you are always 0.25 seconds behind */
    uint64_t reply_time = be64toh(packet.timestamp[3]) + (1ULL<<30);

    packet.li_vn_mode = 044;
    packet.stratum = 16;
    packet.timestamp[0] = 0;
    packet.timestamp[1] = packet.timestamp[3];
    packet.timestamp[2] = packet.timestamp[3];
    packet.timestamp[3] = htobe64(reply_time);
    packet.timestamp[2] = htobe64(reply_time);

    if (len > 48) {
        struct NTS_Query const query = {
            { (void*)"42", 2 },
            key.s2c, key.c2s,
            *param,
            0,
        };
        zero(buf);
        memcpy(buf, &packet, sizeof(packet));
        int resplen = NTS_add_extension_fields(&buf, &query, &unique_id);
        /* TODO: add_extension_fields insists on generating its own uniq id and is not adding cookies */

        assert(resplen > 0);
        sendto(sock, buf, resplen, MSG_CONFIRM, (struct sockaddr*)&client, addrlen);
    } else {
        sendto(sock, &packet, sizeof(packet), MSG_CONFIRM, (struct sockaddr*)&client, addrlen);
    }
}

static void wait_for_nts_ke(void)
{
    /* configure TLS */

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx);

    //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    assert(SSL_CTX_use_certificate_chain_file(ctx, "chain.pem") > 0);
    assert(SSL_CTX_use_PrivateKey_file(ctx, "pkey.pem", SSL_FILETYPE_PEM) > 0);

    SSL *tls = SSL_new(ctx);
    assert(tls);

    /* await the TCP connect */
    BIO *bio = BIO_new_accept("4460");
    assert(bio);
    assert(BIO_do_accept(bio) > 0);
    assert(BIO_do_accept(bio) > 0);
    bio = BIO_pop(bio);
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
        htons(5/*NTPv4Cookie*/),   htons(2), htons(0x3432),
        htons(0/*EndOfMessage*/),  htons(0),
    };

    SSL_write(tls, reply, sizeof(reply));
    SSL_free(tls);
    SSL_CTX_free(ctx);
}

int main(void)
{
    wait_for_nts_ke();
    serve_ntp_request(12345);
    puts("OK");
}
