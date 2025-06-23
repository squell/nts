#include <sys/types.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
} packet = { 043, };

/* check that there is no padding */
static_assert(sizeof(struct ntp_packet) == (4*32 + 4*64) / 8);

static uint64_t get_current_ntp_time(void) {
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);

	uint64_t secs = time.tv_sec + 2208988800; /* wrap around is intended */
	uint64_t frac = time.tv_nsec * 4.294967296;
	return secs << 32 | frac;
}

static uint64_t htonll(uint64_t x) {
	uint32_t parts[2] = { htonl(x >> 32), htonl(x) };
	memcpy(&x, parts, 8);
	return x;
}

static uint64_t ntohll(uint64_t x) {
	uint32_t parts[2];
	memcpy(parts, &x, 8);
	return (uint64_t)ntohl(parts[0]) << 32 | ntohl(parts[1]);
}

int nts_attach_socket(const char *host, int port, int type);

void nts_poll(const char *host, int port, struct NTS *cfg, double *roundtrip_delay, double *time_offset) {
	int sock = nts_attach_socket(host, port, SOCK_DGRAM);
	assert(sock > 0);

	/* take time measurement and send NTP packet */
	uint64_t start;
	packet.timestamp[3] = htonll(start = get_current_ntp_time());

	unsigned char buf[1280];
	memcpy(buf, &packet, sizeof(packet));
	unsigned int buflen = sizeof(packet);
	unsigned char unique[32];
	if(cfg) {
		buflen = add_nts_fields(&buf, cfg);
		assert(buflen > 0);
		memcpy(unique, buf+52, 32);
	}
	assert(write(sock, buf, buflen) == buflen);

	/* read the response */
	ssize_t n = read(sock, &buf, sizeof(buf));
	memcpy(&packet, buf, sizeof(packet));
	assert(n >= (int)sizeof(packet));

	assert((packet.li_vn_mode & 077) == 044);
	if(packet.stratum == 0) {
		printf("Kiss of death: %.4s\n", packet.reference_id);
	}
	assert(packet.stratum != 0);
	assert(start == ntohll(packet.timestamp[1]));

	if(cfg) {
		assert(n > 48);
		struct NTS_receipt rcpt = { 0, };
		assert(parse_nts_fields(&buf, n, cfg, &rcpt));
		assert(rcpt.identifier.data);
		assert(rcpt.identifier.length == 32);
		assert(memcmp(rcpt.identifier.data, unique, 32) == 0);
		assert(rcpt.new_cookie.data);
		assert(rcpt.new_cookie.length <= cfg->cookie.length);
		memcpy(cfg->cookie.data, rcpt.new_cookie.data, rcpt.new_cookie.length);
		cfg->cookie.length = rcpt.new_cookie.length;
	}

	/* perform the calculation */
	long double stamps[5] = { 0, }, *T = stamps;

	T[1] = start;
	T[2] = ntohll(packet.timestamp[2]);
	T[3] = ntohll(packet.timestamp[3]);
	T[4] = get_current_ntp_time();

	long double d = (T[4] - T[1]) - (T[3] - T[2]);
	long double t = (T[2] - T[1]) + (T[3] - T[4]);
	*roundtrip_delay = d / (2ULL<<32);
	*time_offset = t / (1ULL<<32);
}
