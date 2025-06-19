#include <sys/types.h>
#include <sys/socket.h>
#include <sys/random.h>
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

#include "sntp.h"

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

static int finish_nts_packet(unsigned char (*)[1280], struct NTS *);

void nts_poll(const char *host, int port, struct NTS *nts, double *roundtrip_delay, double *time_offset) {
	/* resolve address */
	static struct addrinfo hints;
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo *info;
	assert(getaddrinfo(host, NULL, &hints, &info) == 0);

	/* set port -- is the same memory location for IPv4 and IPv6 */
	assert(info->ai_family == AF_INET6 || info->ai_family == AF_INET);
	((struct sockaddr_in*)info->ai_addr)->sin_port = htons(port);

	/* bind the socket */
	int sock = socket(info->ai_family, SOCK_DGRAM, 0);
	assert(sock != -1);

	assert(connect(sock, info->ai_addr, info->ai_addrlen) == 0);

	/* take time measurement and send NTP packet */
	uint64_t start;
	packet.timestamp[3] = htonll(start = get_current_ntp_time());

	unsigned char buf[1280];
	memcpy(buf, &packet, sizeof(packet));
	unsigned int buflen = sizeof(packet);
	unsigned char unique[32];
	if(nts) {
		buflen = finish_nts_packet(&buf, nts);
		assert(buflen > 0);
		memcpy(unique, buf+52, 32);
	}
	assert(write(sock, buf, buflen) == buflen);

	/* read the response */
	ssize_t n = read(sock, &buf, sizeof(buf));
	memcpy(&packet, buf, sizeof(packet));
	assert(n >= (int)sizeof(packet));

	assert((packet.li_vn_mode & 077) == 044);
	assert(packet.stratum != 0);
	assert(start == ntohll(packet.timestamp[1]));

	if(nts) {
		assert(n > 48);
		/* TODO: not guaranteed to find the extension field here */
		assert(memcmp(unique, buf+52, 32) == 0);
	}

	/* perform the calculation */
	long double stamps[5] = { 0, }, *T = stamps;

	T[1] = start;
	T[2] = ntohll(packet.timestamp[2]);
	T[3] = ntohll(packet.timestamp[3]);
	T[4] = get_current_ntp_time();
	printf("%lu\n", (uint64_t) ntohll(packet.timestamp[0]));
	printf("%lu\n", (uint64_t) ntohll(packet.timestamp[1]));
	printf("%lu\n", (uint64_t) ntohll(packet.timestamp[2]));
	printf("%lu\n", (uint64_t) ntohll(packet.timestamp[3]));

	long double d = (T[4] - T[1]) - (T[3] - T[2]);
	long double t = (T[2] - T[1]) + (T[3] - T[4]);
	*roundtrip_delay = d / (2ULL<<32);
	*time_offset = t / (1ULL<<32);
}

typedef struct {
        unsigned char *data;
        unsigned char *data_end;
} slice;

static size_t capacity(const slice *slice) {
        return slice->data_end - slice->data;
}

static int write_ntp_ext_field(slice *buf, uint16_t type, void *contents, uint16_t len, uint16_t size) {
	/* enforce minimum size */
	if(size < len+4) size = len+4;
	/* pad to a dword boundary */
	unsigned padlen = (size+3) & ~3;

	if(capacity(buf) < padlen) {
		return 0;
	}

	memmove(buf->data+4, contents, len);
	type = htons(type);
	memcpy(buf->data, &type, 2);
	len = htons(len+4);
	memcpy(buf->data+2, &len, 2);

	buf->data += padlen;
	return padlen;
}

/* note: we use this unconventonial way of passing a pointer to let the compiler check array bounds in a limited way */

#define check(expr) if(expr); else return 0;

/* called should make sure that there is enough room in ptxt for holding the plaintext-padded-to-block size + one additional block */
static int write_encrypted_fields(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const slice *info, struct NTS *nts) {
	unsigned char *ctxt_start = ctxt;
	int len;

	EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
	assert(state);

	check(EVP_EncryptInit_ex(state, nts->cipher, NULL, nts->c2s_key, NULL));
	/* leave room for the tag */
	ctxt += 16;

	/* process the associated data first */
	for( ; info->data; info++) {
		check(EVP_EncryptUpdate(state, NULL, &len, info->data, capacity(info)));
		assert((size_t)len == capacity(info));
	}

	/* encrypt data */
	check(EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len));
	assert(len == ptxt_len);
	ctxt += len;

	check(EVP_EncryptFinal_ex(state, ctxt, &len));
	assert(len < 16);
	ctxt += len;

	/* append the AEAD tag */
	check(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, 16, ctxt_start));

	EVP_CIPHER_CTX_free(state);

	return ctxt - ctxt_start;
}

static int finish_nts_packet(unsigned char (*base)[1280], struct NTS *nts) {
	slice buf = { *base, *base + 1280 };

	/* skip beyond regular ntp portion */
	buf.data += sizeof(struct ntp_packet);

	/* generate unique identifier */
	unsigned char rand[32];
	getrandom(rand, sizeof(rand), 0);
	check(write_ntp_ext_field(&buf, 0x104, rand, sizeof(rand), 16));

	/* write cookie field */
	check(write_ntp_ext_field(&buf, 0x204, nts->cookie.data, nts->cookie.length, 16));

	/* --- cobble together the extension fields extension field --- */

	unsigned char const nonce_len = 16; /* NTS servers want this to be 16 */
	unsigned char EF[64] = { 0, nonce_len, 0, 0, };
	assert((nonce_len & 3) == 0);

#ifndef NO_WORKAROUND
	/* bug in OpenSSL: https://github.com/openssl/openssl/issues/26580,
	   which means that a ciphertext HAS TO BE PRESENT */
	unsigned char plain_text[4];
	slice ptxt = { plain_text, plain_text+sizeof(plain_text) };
	int ptxt_len = write_ntp_ext_field(&ptxt, 0x8200, NULL, 0, 0);
#else
	unsigned char *const plain_text = NULL;
	int ptxt_len = 0;
#endif

	/* generate the nonce */
	getrandom(EF+4, nonce_len, 0);

	unsigned char *EF_payload = EF+4+nonce_len;
	slice info[] = {
		{ *base, buf.data },  /* aad */
		{ EF+4, EF_payload }, /* nonce */
		{ NULL },
	};
	uint16_t ctxt_len = write_encrypted_fields(EF_payload, plain_text, ptxt_len, info, nts);

	/* add padding if we used a too-short nonce */
	int ef_len = 4 + ctxt_len + (nonce_len < 16? 16 - nonce_len : nonce_len);

	/* set the ciphertext length */
	ctxt_len = htons(ctxt_len);
	memcpy(EF+2, &ctxt_len, 2);

	check(write_ntp_ext_field(&buf, 0x404, EF, ef_len, 28));

	return buf.data - *base;
}
