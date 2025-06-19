#ifndef NTS_EXTFIELDS_H_EIUERIOWHRIHW
#define NTS_EXTFIELDS_H_EIUERIOWHRIHW

#include "nts.h"

struct NTS {
        struct NTS_cookie cookie;
        uint8_t *c2s_key, *s2c_key;
        EVP_CIPHER *cipher;
};

int add_nts_fields(unsigned char (*base)[1280], const struct NTS *nts);

#endif
