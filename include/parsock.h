#ifndef PARSOCK_H
#define PARSOCK_H

/*
 * libparsock — userspace Secure Parallel Transport (SPT/0.1).
 *
 * One ordered bidirectional byte stream is carried on multiple TCP sockets.
 * A TLS 1.3 control connection authenticates the peers. Data sockets carry
 * custom AEAD records. The synchronous API below is a blocking wrapper around
 * the same session core used by the embedded readiness API.
 *
 * Callbacks run on the thread that entered the library, without internal locks
 * held. They may call ps_submit_send / ps_submit_recv. They must not call
 * ps_on_readable, ps_on_writable, or ps_embed_service reentrantly.
 */

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PS_MAX_SUBFLOWS 64

typedef enum {
    PS_SCALE_FIXED = 0,
    PS_SCALE_AUTO = 1,
    PS_SCALE_ADVISORY = 2
} ps_scale_mode_t;

typedef enum {
    PS_AEAD_AES_256_GCM = 1,
    PS_AEAD_CHACHA20_POLY1305 = 2,
    PS_AEAD_AES_128_GCM = 3
} ps_aead_t;

typedef enum {
    PS_PROTECTION_CONFIDENTIAL = 0,
    PS_PROTECTION_AUTHENTICATED = 1
} ps_protection_t;

enum {
    PS_OK = 0,
    PS_ERR_INVAL = 1,
    PS_ERR_NOMEM = 2,
    PS_ERR_TLS = 3,
    PS_ERR_PROTO = 4,
    PS_ERR_CRYPTO = 5,
    PS_ERR_CLOSED = 6,
    PS_ERR_FLOW = 7,
    PS_ERR_IO = 8,
    PS_ERR_AGAIN = 9,
    PS_ERR_AUTH = 10,
    PS_ERR_LIMIT = 11,
    PS_ERR_TIMEOUT = 12
};

enum {
    PS_STATE_INIT = 0,
    PS_STATE_HANDSHAKE = 1,
    PS_STATE_NEGOTIATING = 2,
    PS_STATE_OPEN = 3,
    PS_STATE_CLOSING = 4,
    PS_STATE_FAILED = 5,
    PS_STATE_CLOSED = 6
};

struct ps_tls_config {
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *server_name;
    int verify_peer;
    int allow_insecure;
};

struct ps_options {
    ps_scale_mode_t scale_mode;
    unsigned min_sockets;
    unsigned max_sockets;
    unsigned initial_sockets;
    unsigned worker_threads;
    uint32_t scale_interval_ms;
    uint64_t min_transfer_size;
    size_t frame_size;
    size_t receive_window;
    ps_aead_t aead;
    ps_protection_t min_protection;
    uint32_t connect_timeout_ms;
    uint32_t io_timeout_ms;
    size_t max_poller_bytes;
    unsigned max_poller_records;
    const struct ps_tls_config *tls;
};

struct ps_stats {
    uint64_t app_bytes_sent;
    uint64_t app_bytes_recv;
    uint64_t records_sent;
    uint64_t records_recv;
    unsigned active_sockets;
    unsigned opening_sockets;
    size_t reassembly_bytes;
    uint64_t goodput_bps;
    uint32_t rtt_us;
    uint32_t peer_scale_request;
    int last_error;
};

struct ps_scale_advice {
    unsigned current_sockets;
    unsigned recommended_sockets;
    uint64_t goodput_bps;
    uint32_t rtt_us;
    int congestion;
    ps_scale_mode_t mode;
};

struct ps_watch {
    int fd;
    int want_read;
    int want_write;
};

typedef struct ps_io_cbs {
    void *ctx;
    void (*want_io)(void *ctx, int fd, int want_read, int want_write);
    void (*stop_io)(void *ctx, int fd);
    void (*stream_readable)(void *ctx);
    void (*stream_writable)(void *ctx);
    void (*session_error)(void *ctx, int error);
    void (*poke)(void *ctx);
} ps_io_cbs;

typedef struct ps_connection ps_connection_t;
typedef struct ps_listener ps_listener_t;
typedef struct ps_session ps_session_t;

void ps_options_init(struct ps_options *opt);
const char *ps_strerror(int err);

ps_connection_t *ps_connect(const char *host, uint16_t port,
                            const struct ps_options *options);
ps_listener_t *ps_listen(const char *host, uint16_t port,
                         const struct ps_options *options);
ps_connection_t *ps_accept(ps_listener_t *listener);
void ps_listener_close(ps_listener_t *listener);
int ps_listener_port(const ps_listener_t *listener, uint16_t *control_port,
                     uint16_t *data_port);

/* Byte count on success. A negative return is -PS_ERR_*. The library copies
   the buffer. A rejected profile does not fail the connection. */
ssize_t ps_send(ps_connection_t *conn, const void *buffer, size_t length);
/* Copies the buffer. Authenticated sends succeed only when both peers set
   min_protection to PS_PROTECTION_AUTHENTICATED. */
ssize_t ps_send_protected(ps_connection_t *conn, const void *buffer, size_t length,
                          ps_protection_t protection);
/* Byte count, 0 at end of stream, or a negative -PS_ERR_* code. */
ssize_t ps_recv(ps_connection_t *conn, void *buffer, size_t length);
int ps_shutdown(ps_connection_t *conn, int how);
int ps_close(ps_connection_t *conn);

int ps_connection_error(const ps_connection_t *conn);
int ps_connection_state(const ps_connection_t *conn);
int ps_connection_stats(const ps_connection_t *conn, struct ps_stats *out);
int ps_connection_advice(const ps_connection_t *conn, struct ps_scale_advice *out);
int ps_rekey(ps_connection_t *conn);

ps_session_t *ps_embed_create(int is_server, const struct ps_options *opt,
                              const ps_io_cbs *cbs);
int ps_embed_set_control(ps_session_t *session, int fd);
int ps_embed_set_data_port(ps_session_t *session, uint16_t port);
int ps_embed_set_peer(ps_session_t *session, const struct sockaddr *addr,
                      socklen_t len);
int ps_embed_adopt_subflow(ps_session_t *session, uint32_t subflow_id, int fd);
int ps_embed_session_id(const ps_session_t *session, uint8_t id[32]);
int ps_embed_service(ps_session_t *session);
int ps_embed_shutdown_write(ps_session_t *session);
void ps_embed_close(ps_session_t *session);

int ps_on_readable(ps_session_t *session, int fd);
int ps_on_writable(ps_session_t *session, int fd);
/* The library copies buffer before ps_submit_send_protected returns.
   completion_context is reserved and is not invoked. */
struct ps_send_descriptor {
    const void *buffer;
    size_t length;
    ps_protection_t protection;
    void *completion_context;
};

int ps_submit_send(ps_session_t *session, const void *data, size_t length,
                   size_t *accepted);
int ps_submit_send_protected(ps_session_t *session, const struct ps_send_descriptor *desc,
                             size_t *accepted);
int ps_submit_recv(ps_session_t *session, void *data, size_t length,
                   size_t *received);
int ps_session_watches(const ps_session_t *session, struct ps_watch *out, int max);
int ps_session_state(const ps_session_t *session);
int ps_session_error(const ps_session_t *session);
int ps_session_stats(const ps_session_t *session, struct ps_stats *out);
int ps_session_advice(const ps_session_t *session, struct ps_scale_advice *out);

int ps_preface_read(int fd, uint8_t session_id[32], uint32_t *subflow_id,
                    int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
