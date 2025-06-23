#include "nts.h"

int NTS_SSL_extract_keys(SSL *ssl, NTS_AEAD_algorithm_type aead, unsigned char *c2s, unsigned char *s2c, int key_capacity) {
	unsigned char *keys[] = { c2s, s2c };
	const char label[30] = { "EXPORTER-network-time-security" }; /* note: this does not include the zero byte */

	int key_size = NTS_AEAD_key_size(aead);
	if(!key_size) {
		return -3;
	} else if(key_size > key_capacity) {
		return -2;
	}

	for(int i=0; i < 2; i++) {
		const unsigned char context[5] = { 0, 0, (aead >> 8) & 0xFF, aead & 0xFF, i };
		if(SSL_export_keying_material(ssl, keys[i], key_size, label, sizeof label, context, sizeof context, 1) != 1) {
			return -1;
		}
	}

	return 0;
}

#ifndef USE_LIBAES_SIV
EVP_CIPHER *NTS_AEAD_cipher(NTS_AEAD_algorithm_type id) {
	const char *name = NTS_AEAD_cipher_name(id);
	return name? EVP_CIPHER_fetch(NULL, name, NULL) : NULL;
}
#endif
