#include <openssl/ssl.h>

#define sym_SSL_export_keying_material SSL_export_keying_material
#define sym_SSL_export_keying_material SSL_export_keying_material
#define sym_SSL_connect SSL_connect
#define sym_SSL_connect SSL_connect
#define sym_SSL_get_error SSL_get_error
#define sym_SSL_get_error SSL_get_error
#define sym_SSL_write SSL_write
#define sym_SSL_write SSL_write
#define sym_SSL_get_error SSL_get_error
#define sym_SSL_get_error SSL_get_error
#define sym_SSL_read SSL_read
#define sym_SSL_read SSL_read
#define sym_SSL_get_error SSL_get_error
#define sym_SSL_get_error SSL_get_error
#define sym_SSL_shutdown SSL_shutdown
#define sym_SSL_shutdown SSL_shutdown
#define sym_SSL_free SSL_free
#define sym_SSL_free SSL_free
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_TLS_client_method TLS_client_method
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_TLS_client_method TLS_client_method
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_TLS_client_method TLS_client_method
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_TLS_client_method TLS_client_method
#define sym_TLS_client_method TLS_client_method
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_TLS_client_method TLS_client_method
#define sym_SSL_CTX_new SSL_CTX_new
#define sym_TLS_client_method TLS_client_method
#define sym_SSL_CTX_set_default_verify_paths SSL_CTX_set_default_verify_paths
#define sym_SSL_CTX_set_default_verify_paths SSL_CTX_set_default_verify_paths
#define sym_BIO_s_socket BIO_s_socket
#define sym_BIO_new BIO_new
#define sym_SSL_set_bio SSL_set_bio
#define sym_BIO_set_fd BIO_set_fd
#define sym_SSL_set_alpn_protos SSL_set_alpn_protos
#define sym_SSL_new SSL_new
#define sym_SSL_set_tlsext_host_name SSL_set_tlsext_host_name
#define sym_SSL_set1_host SSL_set1_host
#define sym_SSL_set_verify SSL_set_verify
#define sym_SSL_CTX_set_min_proto_version SSL_CTX_set_min_proto_version

inline void SSL_freep(SSL** p) {
    SSL_free(*p);
    *p = NULL;
}

inline void SSL_CTX_freep(SSL_CTX** p) {
    SSL_CTX_free(*p);
    *p = NULL;
}

#define dlopen_libssl(x) 0

#define _cleanup_(func) __attribute__((cleanup(func)))

#define MIN(x,y) ((x) < (y)? (x) : (y))
