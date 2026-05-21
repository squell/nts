#include "crypto-util.h"
#include "iovec-util.h"
#include "ssl-util.h"
#include "unaligned.h"
void EVP_CIPHER_freep(EVP_CIPHER** p);
void EVP_CIPHER_CTX_freep(EVP_CIPHER_CTX** p);
void iovec_inc_many(struct iovec *x, int _ignore, size_t n);
void SSL_freep(SSL** p);
void SSL_CTX_freep(SSL_CTX** p);
void unaligned_write_be16(void *buf, uint16_t value);
uint16_t unaligned_read_be16(void *buf);

