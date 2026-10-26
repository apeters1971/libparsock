#ifndef PARSOCK_TLS_H
#define PARSOCK_TLS_H

#include "parsock.h"

#include <openssl/ssl.h>

SSL_CTX *ps_tls_server_ctx(const struct ps_tls_config *cfg);
SSL_CTX *ps_tls_client_ctx(const struct ps_tls_config *cfg);
SSL *ps_tls_wrap(SSL_CTX *ctx, int fd, int is_server, const char *server_name);
int ps_tls_handshake_block(SSL *ssl, int is_server);
int ps_tls_export(SSL *ssl, const uint8_t context[96], uint8_t out[32]);
void ps_tls_log_errors(const char *what);

#endif
