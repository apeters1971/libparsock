#include "tls.h"

#include "log.h"
#include "spt_wire.h"

#include <string.h>

#include <openssl/err.h>

static int base_ctx(SSL_CTX *ctx)
{
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
        return -1;
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
        return -1;
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    return 0;
}

void ps_tls_log_errors(const char *what)
{
    if (what)
        ps_notice("%s", what);
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        ps_notice("openssl: %s", buf);
    }
}

SSL_CTX *ps_tls_server_ctx(const struct ps_tls_config *cfg)
{
    if (!cfg || !cfg->cert_file || !cfg->key_file)
        return NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return NULL;
    if (base_ctx(ctx) != 0 ||
        SSL_CTX_use_certificate_file(ctx, cfg->cert_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        ps_tls_log_errors("server TLS context");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (cfg->verify_peer && !cfg->allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        if (cfg->ca_file && SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
            ps_tls_log_errors("server CA");
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

SSL_CTX *ps_tls_client_ctx(const struct ps_tls_config *cfg)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NULL;
    if (base_ctx(ctx) != 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    int insecure = cfg && cfg->allow_insecure;
    if (!insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (cfg && cfg->ca_file) {
            if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
                ps_tls_log_errors("client CA");
                SSL_CTX_free(ctx);
                return NULL;
            }
        } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            ps_tls_log_errors("default CA");
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    if (cfg && cfg->cert_file && cfg->key_file) {
        if (SSL_CTX_use_certificate_file(ctx, cfg->cert_file, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) != 1) {
            ps_tls_log_errors("client certificate");
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

SSL *ps_tls_wrap(SSL_CTX *ctx, int fd, int is_server, const char *server_name)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
        return NULL;
    BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (!bio) {
        SSL_free(ssl);
        return NULL;
    }
    SSL_set_bio(ssl, bio, bio);
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (is_server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
        if (server_name && server_name[0]) {
            SSL_set_tlsext_host_name(ssl, server_name);
            SSL_set1_host(ssl, server_name);
        }
    }
    return ssl;
}

int ps_tls_handshake_block(SSL *ssl, int is_server)
{
    int rc = is_server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (rc == 1)
        return 0;
    ps_tls_log_errors(is_server ? "SSL_accept" : "SSL_connect");
    return -1;
}

int ps_tls_export(SSL *ssl, const uint8_t context[96], uint8_t out[32])
{
    const char *label = SPT_EXPORTER_LABEL;
    if (SSL_export_keying_material(ssl, out, SPT_ROOT_LEN, label, strlen(label),
                                   context, SPT_EXPORTER_CONTEXT_LEN, 1) != 1) {
        ps_tls_log_errors("SSL_export_keying_material");
        return -1;
    }
    return 0;
}
