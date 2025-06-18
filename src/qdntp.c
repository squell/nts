#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

struct ntp_packet {
	uint8_t li_vn_mode;
	uint8_t stratum;
	uint8_t poll;
	uint8_t precision;
	uint32_t root_delay;
	uint32_t root_dispersion;
	uint32_t reference_id;
	uint64_t timestamp[4];
} packet = { 043, };

/* check that there is no padding */
static_assert(sizeof(struct ntp_packet) == (4*32 + 4*64) / 8);

uint64_t get_current_ntp_time(void) {
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);

	uint64_t secs = time.tv_sec + 2208988800; /* wrap around is intended */
	uint64_t frac = time.tv_nsec * 4.294967296;
	return secs << 32 | frac;
}

uint64_t htonll(uint64_t x) {
	uint32_t parts[2] = { htonl(x >> 32), htonl(x) };
	memcpy(&x, parts, 8);
	return x;
}

uint64_t ntohll(uint64_t x) {
	uint32_t parts[2];
	memcpy(parts, &x, 8);
	return (uint64_t)ntohl(parts[0]) << 32 | ntohl(parts[1]);
}

int main(int argc, char **argv) {
	if(argc <= 1) {
		puts("qdntp [time server]");
		return 1;
	}

	const char *host = argv[1];
	int port = 123;

	/* resolve address */
	static struct addrinfo hints;
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo *info;
	assert(getaddrinfo(host, NULL, &hints, &info) == 0);

	assert(info->ai_family == AF_INET6 || info->ai_family == AF_INET);
	((struct sockaddr_in*)info->ai_addr)->sin_port = htons(port);

	int sock = socket(info->ai_family, SOCK_DGRAM, 0);
	assert(sock != -1);

	assert(connect(sock, info->ai_addr, info->ai_addrlen) == 0);

	uint64_t start;
	packet.timestamp[3] = htonll(start = get_current_ntp_time());
	assert(write(sock, &packet, sizeof(packet)) == sizeof(packet));

	char buf[1024];
	size_t n = read(sock, buf, sizeof(buf));
	assert(n >= sizeof(packet));

	uint64_t stamps[5] = { 0, }, *T = stamps;

	memcpy(&packet, buf, sizeof(packet));
	assert(start == ntohll(packet.timestamp[1]));

	T[1] = start;
	T[2] = ntohll(packet.timestamp[2]);
	T[3] = ntohll(packet.timestamp[3]);
	T[4] = get_current_ntp_time();

	int64_t d = (int64_t)(T[4] - T[1]) - (int64_t)(T[3] - T[2]);
	int64_t t = (int64_t)(T[2] - T[1]) + (int64_t)(T[3] - T[4]);
	printf("roundtrip delay: %g\n", (double)d / (2ULL<<32));
	printf("offset: %g\n", (double)t / (1ULL<<32));

	return 0;
}
