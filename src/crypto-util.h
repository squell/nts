#include <openssl/evp.h>
#include <openssl/opensslv.h>

#define dlopen_libcrypto(x) 0

#define _cleanup_(func) __attribute__((cleanup(func)))

#define sym_EVP_CIPHER_free EVP_CIPHER_free
#define sym_EVP_CIPHER_CTX_new EVP_CIPHER_CTX_new
#define sym_EVP_DecryptUpdate EVP_DecryptUpdate
#define sym_EVP_DecryptFinal_ex EVP_DecryptFinal_ex
#define sym_EVP_CIPHER_fetch EVP_CIPHER_fetch
#define sym_EVP_CIPHER_CTX_ctrl EVP_CIPHER_CTX_ctrl
#define sym_EVP_DecryptInit_ex EVP_DecryptInit_ex
#define sym_EVP_EncryptUpdate EVP_EncryptUpdate
#define sym_EVP_EncryptInit_ex EVP_EncryptInit_ex
#define sym_EVP_EncryptFinal_ex EVP_EncryptFinal_ex

inline void EVP_CIPHER_freep(EVP_CIPHER** p) {
    EVP_CIPHER_free(*p);
    *p = NULL;
}

inline void EVP_CIPHER_CTX_freep(EVP_CIPHER_CTX** p) {
    EVP_CIPHER_CTX_free(*p);
    *p = NULL;
}

