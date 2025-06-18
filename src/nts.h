#ifndef NTS_H_UEHFIOUEWHFHAWOGHRE
#define NTS_H_UEHFIOUEWHFHAWOGHRE

typedef uint16_t NTS_AEAD_algorithm_type;
enum {
        NTS_AEAD_AES_SIV_CMAC_256 = 15,
        NTS_AEAD_AES_SIV_CMAC_512 = 17,
};

enum NTS_error_type {
        NTS_ERROR_UNKNOWN_CRIT_RECORD = 0,
        NTS_BAD_REQUEST = 1,
        NTS_INTERNAL_SERVER_ERROR = 2,

        NTS_UNEXPECTED_WARNING = 0x10000,
        NTS_BAD_RESPONSE = 0x10001,
        NTS_INTERNAL_CLIENT_ERROR = 0x10002,
        NTS_NO_PROTOCOL = 0x10003,
        NTS_NO_AEAD = 0x10004,
        NTS_INSUFFICIENT_DATA = 0x10005,

	NTS_SUCCESS = -1,
};

struct NTS_response {
	enum NTS_error_type error;

	NTS_AEAD_algorithm_type aead_id;

	const char *ntp_server;
	uint16_t ntp_port;

	struct NTS_cookie {
		unsigned char* data;
		size_t length;
	} cookie[9];
};

extern int NTS_encode_request(unsigned char *buffer, size_t buf_size, const NTS_AEAD_algorithm_type *);
extern int NTS_decode_response(unsigned char *buffer, size_t buf_size, struct NTS_response *);

extern int NTS_aead_key_size(NTS_AEAD_algorithm_type);

#endif
