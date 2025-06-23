#ifndef NTS_EXTFIELDS_H_EIUERIOWHRIHW
#define NTS_EXTFIELDS_H_EIUERIOWHRIHW

#include "nts.h"

struct NTS {
        struct NTS_cookie cookie;
        uint8_t *c2s_key, *s2c_key;
#ifndef USE_LIBAES_SIV
        EVP_CIPHER *cipher;
#else
	unsigned int key_len;
#endif
};

struct NTS_receipt {
	struct { unsigned char *data; size_t length; } identifier, new_cookie;
};

int add_nts_fields(unsigned char (*base)[1280], const struct NTS *nts);
int parse_nts_fields(unsigned char (*base)[1280], size_t len, const struct NTS *, struct NTS_receipt *);

#endif
