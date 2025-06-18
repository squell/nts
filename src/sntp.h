#include <openssl/ssl.h>

#include "nts.h"

struct NTS {
	struct NTS_cookie *cookie;
	struct NTS_cookie *nonce;
	EVP_CIPHER_CTX *s2c_cipher, *c2s_cipher;
};

#define ntp_poll(host, port, roundtrip_delay, time_offset) nts_poll(host, port, NULL, roundtrip_delay, time_offset)

void nts_poll(const char *host, int port, struct NTS *, double *roundtrip_delay, double *time_offset);
