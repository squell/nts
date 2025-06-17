#ifndef NTS_H_UEHFIOUEWHFHAWOGHRE
#define NTS_H_UEHFIOUEWHFHAWOGHRE

typedef uint16_t NTS_AEAD_algorithm_type;
enum {
        NTS_AEAD_AES_SIV_CMAC_256 = 15,
        NTS_AEAD_AES_SIV_CMAC_512 = 17,
};

struct NTS_response {
	uint16_t result; /* NTS_error encoding + 1 */

	NTS_AEAD_algorithm_type aead_id;

	const char *ntp_server;
	uint16_t ntp_port;

	struct NTS_cookie {
		unsigned char* data;
		size_t length;
	} cookie[9];
};

extern int NTS_encode_request(unsigned char *buffer, size_t buf_size, const NTS_AEAD_algorithm_type *preferred_crypto);
extern int NTS_decode_response(unsigned char *buffer, size_t buf_size, struct NTS_response *response);

extern uint8_t NTS_supported_aead_algos[];

#endif
