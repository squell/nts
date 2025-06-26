#pragma once

#include "nts.h"

struct NTS {
	struct NTS_cookie cookie;
	const uint8_t *c2s_key, *s2c_key;
#ifndef USE_LIBAES_SIV
	EVP_CIPHER *cipher;
#else
	unsigned int key_len;
#endif
};

struct NTS_receipt {
	struct NTS_cookie identifier, new_cookie;
};

/* Render NTP extension fields in the provided buffer based on the configuration in the NTS struct.
 * If identifier is not NULL, it will hold the generated unique identifier upon success.
 *
 * RETURNS
 * 	The amount of data encoded in bytes. Zero bytes encoded indicates an error (in which case the contents
 * 	of uniq_ident are unspecified)
 */
int NTS_add_extension_fields(unsigned char (*dest)[1280], const struct NTS *nts, unsigned char (*identifier)[32]);

/* Processed the NTP extension fields in the provided buffer based on the configuration in the NTS struct,
 * and make this information available in the NTS_receipt struct.
 *
 * RETURNS
 * 	The amount of data processed in bytes. Zero bytes encoded indicates an error.
 */
int NTS_parse_extension_fields(unsigned char (*src)[1280], size_t src_len, const struct NTS *, struct NTS_receipt *);
