#ifndef NTS_H_UEHFIOUEWHFHAWOGHRE
#define NTS_H_UEHFIOUEWHFHAWOGHRE

typedef uint16_t NTS_AEAD_algorithm_type;
enum {
        NTS_AEAD_AES_SIV_CMAC_256 = 15,
        NTS_AEAD_AES_SIV_CMAC_512 = 17,
};

extern int NTS_encode_request(unsigned char *buffer, size_t buf_size, const NTS_AEAD_algorithm_type *preferred_crypto);

#endif
