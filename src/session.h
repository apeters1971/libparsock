#ifndef PARSOCK_SESSION_H
#define PARSOCK_SESSION_H

#include "parsock.h"

#include <openssl/ssl.h>

struct ps_session_hooks {
    void *ctx;
    void (*register_session)(void *ctx, const uint8_t id[32], ps_session_t *session);
    void (*unregister_session)(void *ctx, ps_session_t *session);
};

ps_session_t *ps_session_create(int is_server, const struct ps_options *opt,
                                SSL_CTX *ctx, const struct ps_tls_config *tls,
                                const ps_io_cbs *cbs);
void ps_session_set_hooks(ps_session_t *session, const struct ps_session_hooks *hooks);
void ps_session_ref(ps_session_t *session);
void ps_session_unref(ps_session_t *session);
void ps_session_stop_workers(ps_session_t *session);
void ps_session_mark_closing(ps_session_t *session);
void ps_session_unregister_now(ps_session_t *session);

int ps_session_attach_ssl(ps_session_t *session, SSL *ssl, int fd, int handshake_done);
SSL *ps_session_ssl(ps_session_t *session);
int ps_session_handshake_done(const ps_session_t *session);
void ps_session_handshake_finished(ps_session_t *session);
int ps_session_is_control(const ps_session_t *session, int fd);
int ps_session_is_connecting(const ps_session_t *session, int fd);

void ps_session_fail(ps_session_t *session, int err);
int ps_session_control_plaintext(ps_session_t *session, const uint8_t *data, size_t len);
void ps_session_control_eof(ps_session_t *session);
int ps_session_take_export(ps_session_t *session, uint8_t context[96]);
void ps_session_install_root(ps_session_t *session, const uint8_t root[32]);
int ps_session_copy_control(ps_session_t *session, uint8_t *dst, size_t cap, size_t *n);
void ps_session_consume_control(ps_session_t *session, size_t n);
int ps_session_ctrl_pending(const ps_session_t *session);
void ps_session_set_ctrl_want(ps_session_t *session, int want_read, int want_write);

int ps_session_ingest(ps_session_t *session, int fd, int *again);
int ps_session_flush(ps_session_t *session, int fd, size_t max_bytes);
int ps_session_on_connected(ps_session_t *session, int fd);
void ps_session_progress(ps_session_t *session);
void ps_session_progress_step(ps_session_t *session);
int ps_session_inline_pending(const ps_session_t *session);
int ps_session_local_pending(const ps_session_t *session);
int ps_session_next_timeout_ms(const ps_session_t *session);
void ps_session_scale_tick(ps_session_t *session);

int ps_session_wait_open(ps_session_t *session, uint32_t timeout_ms);
int ps_session_snap_fds(const ps_session_t *session, int *fds, int *data, int max);
unsigned ps_session_io_lanes(const ps_session_t *session);
ssize_t ps_session_send_wait(ps_session_t *session, const void *buf, size_t len,
                             uint8_t protection, uint32_t timeout_ms);
ssize_t ps_session_recv_wait(ps_session_t *session, void *buf, size_t len,
                             uint32_t timeout_ms);
int ps_session_shutdown_write(ps_session_t *session);
int ps_session_rekey_wait(ps_session_t *session, uint32_t timeout_ms);
int ps_session_wait_flush(ps_session_t *session, uint32_t timeout_ms);
int ps_session_transport(const ps_session_t *session);
int ps_session_is_rdma_fd(const ps_session_t *session, int fd);
int ps_session_rdma_service(ps_session_t *session);
struct ps_rdma *ps_session_rdma_handle(ps_session_t *session);
int ps_session_is_quic_fd(const ps_session_t *session, int fd);
int ps_session_quic_service(ps_session_t *session);

#endif
