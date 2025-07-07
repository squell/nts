#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <threads.h>
#include <openssl/ssl.h>

typedef uint16_t NTS_AEAD_algorithm_type;
enum {
	NTS_AEAD_AES_SIV_CMAC_256 = 15,
	NTS_AEAD_AES_SIV_CMAC_384 = 16,
	NTS_AEAD_AES_SIV_CMAC_512 = 17,
	NTS_AEAD_AES_128_GCM_SIV  = 30,
	NTS_AEAD_AES_256_GCM_SIV  = 31,
};

struct NTS_AEAD_param {
	uint8_t aead_id, key_size, block_size, nonce_size;
	bool tag_first, nonce_is_iv;
	const char *cipher_name;
};

enum NTS_error_type {
	NTS_ERROR_UNKNOWN_CRIT_RECORD = 0,
	NTS_ERROR_BAD_REQUEST = 1,
	NTS_ERROR_INTERNAL_SERVER_ERROR = 2,

	NTS_UNEXPECTED_WARNING = 0x10000,
	NTS_BAD_RESPONSE = 0x10001,
	NTS_INTERNAL_CLIENT_ERROR = 0x10002,
	NTS_NO_PROTOCOL = 0x10003,
	NTS_NO_AEAD = 0x10004,
	NTS_INSUFFICIENT_DATA = 0x10005,

	NTS_SUCCESS = -1,
};

struct NTS_agreement {
	enum NTS_error_type error;

	NTS_AEAD_algorithm_type aead_id;

	const char *ntp_server;
	uint16_t ntp_port;

	struct NTS_cookie {
		unsigned char* data;
		size_t length;
	} cookie[8];
};

/* Encode a NTS KE request in the buffer of the provided size. If the third argument is not NULL,
 * it must point to a NULL-terminated array of AEAD_algorithm-types that indicate the preferred AEAD
 * algorithms (otherwise a sane default it used).
 *
 * RETURNS
 *      non-zero number of bytes encoded upon success
 *      negative value upon failure (not enough room in buffer)
 */
int NTS_encode_request(unsigned char *buffer, size_t buf_size, const NTS_AEAD_algorithm_type[]);

/* Decode a NTS KE reponse in the buffer of the provided size, and write the result to the NTS_reponse
 * struct.
 *
 * RETURNS
 *      0 upon success
 *      -1 upon failure (writes the error code to NTS_agreement->error)
 */
int NTS_decode_response(unsigned char *buffer, size_t buf_size, struct NTS_agreement *);

/* The following three functions provide runtime information about the chosen AEAD algorithm:
 * - key size requirement in bytes
 * - OpenSSL name of the AEAD algorithm
 * - Fetched EVP_CIPHER for the AEAD algorithm (when SIV is provided by OpenSSL only)
 */

const struct NTS_AEAD_param* NTS_AEAD_param(NTS_AEAD_algorithm_type);

/* Perform key extraction on the SSL object using the specified algorithm_type. C2S and S2C must point to
 * buffers that provide key_capacity amount of bytes
 *
 * RETURNS
 *      0 upon success
 *      a negative value upon failure:
 *              -1 OpenSSL error
 *              -2 not enough space in buffer
 *              -3 unkown AEAD
 */
int NTS_SSL_extract_keys(
		SSL *,
		NTS_AEAD_algorithm_type,
		unsigned char *c2s,
		unsigned char *s2c,
		int key_capacity);

/* Setup a SSL object that is connected to hostname:port, ready to begin a TLS handshake.
 * Accepted certificates are loaded using the provided function pointer
 *      (recommended: SSL_CTX_set_default_verify_paths).
 *
 * To use blocking I/O, set the last argument to true.
 *
 * RETURNS
 *      A pointer to a ready SSL object, NULL upon failure (and then the error is stored in NTS_SSL_error)
 */
SSL* NTS_SSL_setup(const char *hostname, int port, int load_certs(SSL_CTX *), int blocking);

extern thread_local enum NTS_SSL_error_type {
	NTS_SSL_INTERNAL_ERROR,
	NTS_SSL_NO_CONNECTION,
} NTS_SSL_error;
