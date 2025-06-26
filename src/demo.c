#include <string.h>
#include <assert.h>

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "nts.h"
#include "nts_extfields.h"
#include "sntp.h"

unsigned char buffer[65536];

int main(int argc, char **argv)
{
	const char *hostname = "ptbtime1.ptb.de";
	if(argc > 1) {
		hostname = argv[1];
	}
	int ntp_port = 123;
	int port = 4460;

	SSL *ssl = NTS_SSL_setup(hostname, port, SSL_CTX_set_default_verify_paths, 1);
	assert(ssl);

	assert(SSL_connect(ssl) == 1);

	uint16_t pref_arr[4] = { 0, }, *prefs = NULL;
	if(argc > 5) {
		printf("too many AEAD's specified\n");
		goto end;
	} else if(argc > 2) {
		prefs = pref_arr;
		for(char **arg = argv+2; *arg; arg++) {
			#define parse(type) if(strstr(#type, *arg)) *prefs++ = NTS_##type
			if(strnlen(*arg, 3) < 3) continue; else
			parse(AEAD_AES_SIV_CMAC_256); else
			parse(AEAD_AES_SIV_CMAC_384); else
			parse(AEAD_AES_SIV_CMAC_512); else {
				printf("unknown AEAD: %s\n", *arg);
				goto end;
			}
			#undef parse
		}
		prefs = pref_arr;
	}

	int size = NTS_encode_request(buffer, sizeof(buffer), prefs);

	size_t written, readbytes;

	if(!SSL_write_ex(ssl, buffer, size, &written)) {
		printf("failed to write request\n");
		goto end;
	}

	/*
	 * Get up to sizeof(buf) bytes of the response. We keep reading until the
	 * server closes the connection.
	 */
	struct NTS nts;

	while(SSL_read_ex(ssl, buffer, sizeof(buffer), &readbytes)) {
		struct NTS_response NTS;
		assert(NTS_decode_response(buffer, readbytes, &NTS) >= 0);
		if(NTS.error >= 0) {
			printf("NTS error: 0x%04X\n", NTS.error);
			goto end;
		}

		const char *cipher = NTS_AEAD_cipher_name(NTS.aead_id);
		assert(cipher != NULL);
		printf("selected AEAD: %s\n", cipher);

		#define FALLBACK(x, y) (x? x : y)
		hostname = FALLBACK(NTS.ntp_server, hostname);
		ntp_port = FALLBACK(NTS.ntp_port, ntp_port);

		printf("ntp server: %s:%d\n", hostname, ntp_port);
		for(int i=0; NTS.cookie[i].data; i++) {
			printf("cookie%d: ", i+1);
			for(size_t n=0; n < NTS.cookie[i].length; n++)
					printf("%02x", NTS.cookie[i].data[n]);
			printf("\n");
		}

		static unsigned char c2s[64], s2c[64];
		nts = (struct NTS) {
#ifndef USE_LIBAES_SIV
			.cipher = NTS_AEAD_cipher(NTS.aead_id),
#else
			.key_len = NTS_AEAD_key_size(NTS.aead_id),
#endif
			.c2s_key = c2s,
			.s2c_key = s2c,
			.cookie = *NTS.cookie,
		};

		assert(NTS_SSL_extract_keys(ssl, NTS.aead_id, c2s, s2c, 64) == 0);
	}

	assert(SSL_get_error(ssl, 0) == SSL_ERROR_ZERO_RETURN);
	assert(SSL_shutdown(ssl) == 1);

	double delay, offset;
	nts_poll(hostname, ntp_port, &nts, &delay, &offset);
	printf("cookie*: ");
	for(size_t i=0; i < nts.cookie.length; i++)
		printf("%02x", nts.cookie.data[i]);
	printf("\n");
	printf("roundtrip delay: %f\n", delay);
	printf("offset: %f\n", offset);

	SSL_free(ssl);
	return 0;
 end:
	ERR_print_errors_fp(stderr);

	SSL_free(ssl);
	return -1;
}
