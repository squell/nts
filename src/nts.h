#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <threads.h>
#include <openssl/ssl.h>

/* algorithm type is not made into a full enum since it eases ptr-conversions */
typedef uint16_t NTS_AEADAlgorithmType;
enum {
        NTS_AEAD_AES_SIV_CMAC_256 = 15,
        NTS_AEAD_AES_SIV_CMAC_384 = 16,
        NTS_AEAD_AES_SIV_CMAC_512 = 17,
        NTS_AEAD_AES_128_GCM_SIV  = 30,
        NTS_AEAD_AES_256_GCM_SIV  = 31,
};

typedef struct NTS_AEADParam {
        uint8_t aead_id, key_size, block_size, nonce_size;
        bool tag_first, nonce_is_iv;
        const char *cipher_name;
} NTS_AEADParam;

typedef enum NTS_ErrorType {
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
} NTS_ErrorType;

typedef struct NTS_Agreement {
        enum NTS_ErrorType error;

        NTS_AEADAlgorithmType aead_id;

        const char *ntp_server;
        uint16_t ntp_port;

        struct NTS_Cookie {
                uint8_t *data;
                size_t length;
        } cookie[8];
} NTS_Agreement;

/* Encode a NTS KE request in the buffer of the provided size. If the third argument is not NULL,
 * it must point to a NULL-terminated array of AEAD_algorithm-types that indicate the preferred AEAD
 * algorithms (otherwise a sane default it used).
 *
 * RETURNS
 *      non-zero number of bytes encoded upon success
 *      negative value upon failure (not enough room in buffer)
 */
int NTS_encode_request(uint8_t *buffer, size_t buf_size, const NTS_AEADAlgorithmType[]);

/* Decode a NTS KE reponse in the buffer of the provided size, and write the result to the NTS_reponse
 * struct.
 *
 * RETURNS
 *      0 upon success
 *      -1 upon failure (writes the error code to NTS_Agreement->error)
 */
int NTS_decode_response(uint8_t *buffer, size_t buf_size, struct NTS_Agreement *);

/* The following three functions provide runtime information about the chosen AEAD algorithm:
 * - key size requirement in bytes
 * - OpenSSL name of the AEAD algorithm
 * - Fetched EVP_CIPHER for the AEAD algorithm (when SIV is provided by OpenSSL only)
 */

const struct NTS_AEADParam* NTS_GetParam(NTS_AEADAlgorithmType);

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
int NTS_SSL_extract_keys(SSL *, NTS_AEADAlgorithmType, uint8_t *c2s, uint8_t *s2c, int key_capacity);

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

typedef enum NTS_TLSErrorType {
        NTS_SSL_INTERNAL_ERROR,
        NTS_SSL_NO_CONNECTION,
} NTS_TLSErrorType;

extern thread_local enum NTS_TLSErrorType NTS_SSL_error;
