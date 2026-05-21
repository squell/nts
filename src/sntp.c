#include <sys/types.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "sntp.h"
#include "nts_extfields.h"

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

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

/* check that there is no padding */
typedef int ntp_padding_check[sizeof(struct ntp_packet) == 48];

static uint64_t get_current_ntp_time(void) {
        struct timespec time;
        clock_gettime(CLOCK_REALTIME, &time);

        uint64_t secs = time.tv_sec + 2208988800; /* wrap around is intended */
        uint64_t frac = time.tv_nsec * ((1ULL<<32) / 1E9L);
        return secs << 32 | frac;
}

int NTS_attach_socket(const char *host, int port, int type);

static uint64_t byte_order(uint64_t value) {
        uint32_t hi = htonl(value >> 32);
        uint32_t lo = htonl(value & 0xFFFFFFFF);
        unsigned char *bytes = (void*) &value;
        memcpy(bytes + 0, &hi, 4);
        memcpy(bytes + 4, &lo, 4);
        return value;
}

void nts_poll(const char *host, int port, struct NTS_Query *cfg, double *roundtrip_delay, double *time_offset, int *new_cookies) {
        struct ntp_packet packet = { 043, };

        int sock = NTS_attach_socket(host, port, SOCK_DGRAM);
        assert(sock > 0);

        /* take time measurement and send NTP packet */
        uint64_t start;
        packet.timestamp[3] = byte_order(start = get_current_ntp_time());

        unsigned char buf[1280];
        memcpy(buf, &packet, sizeof(packet));
        unsigned int buflen = sizeof(packet);
        unsigned char unique[32];
        if (cfg) {
                buflen = NTS_add_extension_fields(buf, cfg, &unique);
                assert(buflen > 0);
        }
        assert(write(sock, buf, buflen) == (ssize_t)buflen);

        /* read the response */
        ssize_t n = read(sock, &buf, sizeof(buf));
        memcpy(&packet, buf, sizeof(packet));
        assert(n >= (int)sizeof(packet));
        close(sock);

        assert((packet.li_vn_mode & 077) == 044);
        if (packet.stratum == 0)
                printf("Kiss of death: %.4s\n", packet.reference_id);

        assert(packet.stratum != 0);
        assert(start == byte_order(packet.timestamp[1]));

        if (cfg) {
                assert(n > 48);
                struct NTS_Receipt rcpt = { 0, };
                assert(NTS_parse_extension_fields(buf, n, cfg, &rcpt));
                assert(rcpt.identifier);
                assert(memcmp(rcpt.identifier, unique, 32) == 0);
                assert(rcpt.new_cookie->data);
                assert(rcpt.new_cookie->length <= cfg->cookie.length);
                if (new_cookies) {
                        *new_cookies = 0;
                        while (*new_cookies < 8 && rcpt.new_cookie[*new_cookies].data) {
                                (*new_cookies)++;
                        }
                }
                memcpy(cfg->cookie.data, rcpt.new_cookie->data, rcpt.new_cookie->length);
                cfg->cookie.length = rcpt.new_cookie->length;
        }

        /* perform the calculation */
        long double stamps[5] = { 0, }, *T = stamps;

        T[1] = start;
        T[2] = byte_order(packet.timestamp[2]);
        T[3] = byte_order(packet.timestamp[3]);
        T[4] = get_current_ntp_time();

        long double d = (T[4] - T[1]) - (T[3] - T[2]);
        long double t = ((T[2] - T[1]) + (T[3] - T[4])) / 2;
        *roundtrip_delay = d / (1ULL<<32);
        *time_offset = t / (1ULL<<32);
}
