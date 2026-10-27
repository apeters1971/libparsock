#include "session.h"

#include "tls.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

static int tls_peer_closed(int n, int err)
{
    if (n == 0 || err == SSL_ERROR_ZERO_RETURN)
        return 1;
    if (err == SSL_ERROR_SYSCALL &&
        (errno == 0 || errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN ||
         errno == ECONNABORTED))
        return 1;
    if (err == SSL_ERROR_SSL && ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        ERR_clear_error();
        return 1;
    }
    return 0;
}

static int pump_control(ps_session_t *session)
{
    SSL *ssl = ps_session_ssl(session);
    if (!ssl)
        return -PS_ERR_TLS;
    if (!ps_session_handshake_done(session)) {
        int rc = SSL_do_handshake(ssl);
        if (rc == 1) {
            ps_session_handshake_finished(session);
        } else {
            int err = SSL_get_error(ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                ps_session_set_ctrl_want(session, err == SSL_ERROR_WANT_READ,
                                         err == SSL_ERROR_WANT_WRITE);
                return -PS_ERR_AGAIN;
            }
            ps_tls_log_errors("handshake");
            ps_session_fail(session, PS_ERR_TLS);
            return -PS_ERR_TLS;
        }
    }

    int peer_closed = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t buf[16384];
        int n = SSL_read(ssl, buf, (int)sizeof(buf));
        if (n > 0) {
            int rc = ps_session_control_plaintext(session, buf, (size_t)n);
            if (rc < 0 && rc != -PS_ERR_AGAIN)
                return rc;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            break;
        if (tls_peer_closed(n, err)) {
            ps_session_control_eof(session);
            peer_closed = 1;
            break;
        }
        ps_tls_log_errors("SSL_read");
        ps_session_fail(session, PS_ERR_TLS);
        return -PS_ERR_TLS;
    }
    if (peer_closed) {
        ps_session_set_ctrl_want(session, 0, 0);
        return PS_OK;
    }

    uint8_t context[96];
    if (ps_session_take_export(session, context)) {
        uint8_t root[32];
        if (ps_tls_export(ssl, context, root) != 0) {
            ps_session_fail(session, PS_ERR_TLS);
            return -PS_ERR_TLS;
        }
        ps_session_install_root(session, root);
        OPENSSL_cleanse(root, sizeof(root));
    }
    ps_session_progress(session);

    int want_write = 0;
    for (;;) {
        uint8_t buf[16384];
        size_t have = 0;
        if (ps_session_copy_control(session, buf, sizeof(buf), &have) != 0 || have == 0)
            break;
        int n = SSL_write(ssl, buf, (int)have);
        if (n > 0) {
            ps_session_consume_control(session, (size_t)n);
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            want_write = 1;
            break;
        }
        if (tls_peer_closed(n, err)) {
            ps_session_control_eof(session);
            ps_session_set_ctrl_want(session, 0, 0);
            return PS_OK;
        }
        ps_tls_log_errors("SSL_write");
        ps_session_fail(session, PS_ERR_TLS);
        return -PS_ERR_TLS;
    }
    if (ps_session_ctrl_pending(session))
        want_write = 1;
    ps_session_set_ctrl_want(session, 1, want_write);
    ps_session_progress(session);
    return ps_session_rdma_service(session);
}

int ps_on_readable(ps_session_t *session, int fd)
{
    if (!session || fd < 0)
        return -PS_ERR_INVAL;
    if (ps_session_is_rdma_fd(session, fd))
        return ps_session_rdma_service(session);
    if (ps_session_is_control(session, fd))
        return pump_control(session);
    int again = 0;
    int rc = ps_session_ingest(session, fd, &again);
    ps_session_progress(session);
    if (rc < 0)
        return rc;
    return again ? -PS_ERR_AGAIN : PS_OK;
}

int ps_on_writable(ps_session_t *session, int fd)
{
    if (!session || fd < 0)
        return -PS_ERR_INVAL;
    if (ps_session_is_control(session, fd))
        return pump_control(session);
    if (ps_session_is_connecting(session, fd)) {
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
            ps_session_fail(session, PS_ERR_IO);
            return -PS_ERR_IO;
        }
        struct sockaddr_storage peer;
        socklen_t plen = sizeof(peer);
        if (getpeername(fd, (struct sockaddr *)&peer, &plen) != 0)
            return -PS_ERR_AGAIN;
        int rc = ps_session_on_connected(session, fd);
        ps_session_progress(session);
        return rc;
    }
    int rc = ps_session_flush(session, fd, 1024 * 1024);
    ps_session_progress(session);
    return rc;
}
