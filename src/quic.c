#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include "quic.h"

#include "log.h"
#include "net.h"
#include "spt_wire.h"
#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#if defined(PARSOCK_HAVE_QUIC)

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

/* Flow-control window and the rx/tx buffer that holds it. A 1 MiB
   window refills once per acknowledgement delay, which measured
   about 40 MB/s. 16 MiB leaves room for a millisecond of delay. */
#define QUIC_WINDOW (16u << 20)
#define QUIC_CIDLEN 18u
#define QUIC_BURST 32
#define QUIC_WRITE_MAX 1024

struct qconn {
    int used;
    int dead;
    int bound;
    int is_server;
    int connected;
    int hs_done;
    int stream_ready;
    int bidi_tried;
    int fin;
    uint32_t lane;
    int fd;
    ngtcp2_conn *conn;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl;
    ngtcp2_crypto_conn_ref ref;
    int64_t stream_id;
    ngtcp2_cid original_dcid;
    int have_odcid;
    struct sockaddr_storage local;
    socklen_t local_len;
    struct sockaddr_storage remote;
    socklen_t remote_len;
    uint8_t *rx;
    size_t rx_len;
    size_t rx_cap;
    uint8_t *tx;
    size_t tx_cap;
    size_t tx_pos;
    size_t tx_len;
    size_t tx_sent;
    uint64_t tx_ack;
    uint8_t pending[QUIC_BURST][1500];
    uint16_t pending_len[QUIC_BURST];
    int pending_n;
    int pending_off;
    int need_write;
    struct ps_quic *parent;
};

struct ps_quic {
    int is_server;
    int fd;
    int broken;
    SSL_CTX *ctx;
    unsigned max_lanes;
    char *server_name;
    struct qconn conns[PS_QUIC_MAX_LANES];
};

static const unsigned char SPT_ALPN[] = {3, 's', 'p', 't'};

static ngtcp2_conn *crypto_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return ref ? (ngtcp2_conn *)ref->user_data : NULL;
}

static ngtcp2_tstamp qnow(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    if (destlen > 0 && RAND_bytes(dest, (int)destlen) != 1)
        memset(dest, 0, destlen);
}

static int new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen,
                      void *user_data)
{
    (void)conn;
    (void)user_data;
    if (cidlen == 0 || cidlen > NGTCP2_MAX_CIDLEN)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    if (RAND_bytes(cid->data, (int)cidlen) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

#if NGTCP2_VERSION_NUM >= 0x011600
static int new_cid_cb2(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                       size_t cidlen, void *user_data)
{
    return new_cid_cb(conn, cid, token->data, cidlen, user_data);
}
#endif

static int recv_stream_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
                          const uint8_t *data, size_t datalen, void *user_data,
                          void *stream_user_data)
{
    (void)conn;
    (void)offset;
    (void)stream_user_data;
    struct qconn *c = (struct qconn *)user_data;
    if (c->stream_ready && stream_id != c->stream_id)
        return 0;
    c->stream_id = stream_id;
    c->stream_ready = 1;
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
        c->fin = 1;
    if (datalen == 0)
        return 0;
    if (!data || c->rx_len + datalen > c->rx_cap) {
        c->dead = 1;
        return 0;
    }
    memcpy(c->rx + c->rx_len, data, datalen);
    c->rx_len += datalen;
    return 0;
}

static int handshake_cb(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    ((struct qconn *)user_data)->hs_done = 1;
    return 0;
}

static int acked_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen,
                    void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_user_data;
    struct qconn *c = (struct qconn *)user_data;
    if (!c->stream_ready || stream_id != c->stream_id || datalen == 0)
        return 0;
    /* Failing this callback makes ngtcp2 1.22 walk an acknowledgement
       iterator that is already at the beginning and abort. */
    if (offset < c->tx_ack) {
        uint64_t end = offset + datalen;
        if (end <= c->tx_ack)
            return 0;
        datalen = end - c->tx_ack;
        offset = c->tx_ack;
    }
    if (offset != c->tx_ack || datalen > c->tx_len)
        return 0;
    c->tx_pos += (size_t)datalen;
    c->tx_len -= (size_t)datalen;
    c->tx_ack += datalen;
    if (c->tx_sent >= (size_t)datalen)
        c->tx_sent -= (size_t)datalen;
    else
        c->tx_sent = 0;
    if (c->tx_len == 0 || c->tx_pos > 65536) {
        if (c->tx_len)
            memmove(c->tx, c->tx + c->tx_pos, c->tx_len);
        c->tx_pos = 0;
    }
    return 0;
}

static int stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                           uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)final_size;
    (void)app_error_code;
    (void)stream_user_data;
    ((struct qconn *)user_data)->dead = 1;
    return 0;
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, SPT_ALPN, sizeof(SPT_ALPN), in,
                              inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

static void fill_callbacks(ngtcp2_callbacks *cb, int is_server)
{
    memset(cb, 0, sizeof(*cb));
    if (is_server)
        cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    else {
        cb->client_initial = ngtcp2_crypto_client_initial_cb;
        cb->recv_retry = ngtcp2_crypto_recv_retry_cb;
    }
    cb->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb->handshake_completed = handshake_cb;
    cb->encrypt = ngtcp2_crypto_encrypt_cb;
    cb->decrypt = ngtcp2_crypto_decrypt_cb;
    cb->hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb->recv_stream_data = recv_stream_cb;
    cb->acked_stream_data_offset = acked_cb;
    cb->stream_reset = stream_reset_cb;
    cb->rand = rand_cb;
#if NGTCP2_VERSION_NUM >= 0x011600
    cb->get_new_connection_id2 = new_cid_cb2;
    cb->get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
#else
    cb->get_new_connection_id = new_cid_cb;
    cb->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
#endif
    cb->update_key = ngtcp2_crypto_update_key_cb;
    cb->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
}

static void fill_params(ngtcp2_transport_params *params)
{
    ngtcp2_transport_params_default(params);
    params->initial_max_stream_data_bidi_local = QUIC_WINDOW;
    params->initial_max_stream_data_bidi_remote = QUIC_WINDOW;
    params->initial_max_stream_data_uni = QUIC_WINDOW;
    params->initial_max_data = QUIC_WINDOW;
    params->initial_max_streams_bidi = 1;
    params->initial_max_streams_uni = 0;
    params->max_idle_timeout = 120 * NGTCP2_SECONDS;
    params->max_udp_payload_size = 65527;
    params->max_ack_delay = NGTCP2_MILLISECONDS;
    params->disable_active_migration = 1;
}

static void tune_settings(ngtcp2_settings *settings, ngtcp2_tstamp now)
{
    settings->initial_ts = now;
    settings->handshake_timeout = 15 * NGTCP2_SECONDS;
    settings->no_pmtud = 1;
    settings->initial_rtt = NGTCP2_MILLISECONDS;
    settings->ack_thresh = 1;
    settings->max_window = QUIC_WINDOW;
    settings->max_stream_window = QUIC_WINDOW;
}

static int random_cid(ngtcp2_cid *cid)
{
    cid->datalen = QUIC_CIDLEN;
    if (RAND_bytes(cid->data, QUIC_CIDLEN) != 1)
        return -1;
    return 0;
}

static void conn_clear(struct qconn *c)
{
    if (!c->used && !c->conn && !c->ssl)
        return;
    if (c->conn)
        ngtcp2_conn_del(c->conn);
    c->conn = NULL;
    if (c->ssl)
        SSL_set_app_data(c->ssl, NULL);
    if (c->ossl)
        ngtcp2_crypto_ossl_ctx_del(c->ossl);
    c->ossl = NULL;
    if (c->ssl)
        SSL_free(c->ssl);
    c->ssl = NULL;
    if (c->fd >= 0)
        close(c->fd);
    free(c->rx);
    free(c->tx);
    struct ps_quic *parent = c->parent;
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->parent = parent;
}

static int conn_buffers(struct qconn *c)
{
    c->rx_cap = QUIC_WINDOW;
    c->tx_cap = QUIC_WINDOW;
    c->rx = (uint8_t *)malloc(c->rx_cap);
    c->tx = (uint8_t *)malloc(c->tx_cap);
    c->fd = -1;
    if (!c->rx || !c->tx)
        return -1;
    return 0;
}

static int conn_tls(struct qconn *c, SSL_CTX *ctx, const char *server_name)
{
    if (ngtcp2_crypto_ossl_ctx_new(&c->ossl, NULL) != 0)
        return -1;
    ngtcp2_conn_set_tls_native_handle(c->conn, c->ossl);
    c->ssl = SSL_new(ctx);
    if (!c->ssl)
        return -1;
    ngtcp2_crypto_ossl_ctx_set_ssl(c->ossl, c->ssl);
    c->ref.get_conn = crypto_get_conn;
    c->ref.user_data = c->conn;
    if (c->is_server) {
        if (ngtcp2_crypto_ossl_configure_server_session(c->ssl) != 0)
            return -1;
        SSL_set_app_data(c->ssl, &c->ref);
        SSL_set_accept_state(c->ssl);
        SSL_set_quic_tls_early_data_enabled(c->ssl, 1);
    } else {
        if (ngtcp2_crypto_ossl_configure_client_session(c->ssl) != 0)
            return -1;
        SSL_set_app_data(c->ssl, &c->ref);
        SSL_set_connect_state(c->ssl);
        if (server_name && server_name[0] && ps_tls_set_peer_name(c->ssl, server_name) != 0)
            return -1;
        if (SSL_set_alpn_protos(c->ssl, SPT_ALPN, sizeof(SPT_ALPN)) != 0)
            return -1;
    }
    return 0;
}

static int udp_socket(int family)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    int buf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    if (ps_set_nonblock(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_udp(struct qconn *c, int fd, const uint8_t *data, size_t len)
{
    ssize_t n;
    if (c->connected)
        n = send(fd, data, len, 0);
    else
        n = sendto(fd, data, len, 0, (struct sockaddr *)&c->remote, c->remote_len);
    if (n < 0) {
        if (errno == EINTR)
            return send_udp(c, fd, data, len);
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 1;
        return -1;
    }
    return (size_t)n == len ? 0 : -1;
}

static int send_many(struct qconn *c, int fd, uint8_t pkts[][1500], const uint16_t *lens, int n,
                     int *sent_out)
{
    int sent = 0;
    if (sent_out)
        *sent_out = 0;
    if (n <= 0)
        return 0;
#if defined(__linux__)
    struct mmsghdr msgs[QUIC_BURST];
    struct iovec iov[QUIC_BURST];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < n; i++) {
        iov[i].iov_base = pkts[i];
        iov[i].iov_len = lens[i];
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        if (!c->connected) {
            msgs[i].msg_hdr.msg_name = &c->remote;
            msgs[i].msg_hdr.msg_namelen = c->remote_len;
        }
    }
    while (sent < n) {
        int rc = sendmmsg(fd, msgs + sent, (unsigned)(n - sent), 0);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return -1;
        }
        if (rc == 0)
            break;
        sent += rc;
    }
#else
    while (sent < n) {
        int rc = send_udp(c, fd, pkts[sent], lens[sent]);
        if (rc > 0)
            break;
        if (rc < 0)
            return -1;
        sent++;
    }
#endif
    if (sent_out)
        *sent_out = sent;
    return sent < n ? 1 : 0;
}

static int flush_pending(struct qconn *c, int fd)
{
    if (c->pending_off >= c->pending_n)
        return 0;
    int sent = 0;
    int rc = send_many(c, fd, c->pending + c->pending_off, c->pending_len + c->pending_off,
                        c->pending_n - c->pending_off, &sent);
    if (rc < 0)
        return -1;
    c->pending_off += sent;
    if (c->pending_off >= c->pending_n) {
        c->pending_off = 0;
        c->pending_n = 0;
        return 0;
    }
    return 1;
}

static int emit_bufs(struct qconn *c, int fd, uint8_t bufs[][1500], const uint16_t *lens, int nbuf)
{
    int sent = 0;
    int rc = send_many(c, fd, bufs, lens, nbuf, &sent);
    if (rc < 0)
        return -1;
    if (rc > 0) {
        int left = nbuf - sent;
        for (int k = 0; k < left; k++) {
            memcpy(c->pending[k], bufs[sent + k], lens[sent + k]);
            c->pending_len[k] = lens[sent + k];
        }
        c->pending_off = 0;
        c->pending_n = left;
        return 1;
    }
    return 0;
}

static void credit_read(struct qconn *c, size_t n)
{
    if (!c->conn || !c->stream_ready || n == 0)
        return;
    ngtcp2_conn_extend_max_stream_offset(c->conn, c->stream_id, n);
    ngtcp2_conn_extend_max_offset(c->conn, n);
    c->need_write = 1;
}

static int kill_conn(struct qconn *c, int bound_is_fatal)
{
    int fatal = c->bound && bound_is_fatal;
    if (c->parent && fatal)
        c->parent->broken = 1;
    conn_clear(c);
    return fatal ? -1 : 0;
}

static int write_conn(struct qconn *c, int fd, ngtcp2_tstamp ts)
{
    if (c->dead || !c->conn)
        return 0;
    int blocked = flush_pending(c, fd);
    if (blocked != 0)
        return blocked;
    if (!c->is_server && c->hs_done && !c->stream_ready && !c->bidi_tried) {
        int64_t id = -1;
        int rv = ngtcp2_conn_open_bidi_stream(c->conn, &id, NULL);
        c->bidi_tried = rv != NGTCP2_ERR_STREAM_ID_BLOCKED;
        if (rv == 0) {
            c->stream_id = id;
            c->stream_ready = 1;
        } else if (rv != NGTCP2_ERR_STREAM_ID_BLOCKED) {
            c->dead = 1;
            return kill_conn(c, 1);
        }
    } else if (!c->is_server && c->hs_done && !c->stream_ready && c->bidi_tried == 0) {
        int64_t id = -1;
        int rv = ngtcp2_conn_open_bidi_stream(c->conn, &id, NULL);
        if (rv == 0) {
            c->stream_id = id;
            c->stream_ready = 1;
            c->bidi_tried = 1;
        }
    }
    ngtcp2_tstamp exp = ngtcp2_conn_get_expiry(c->conn);
    if (exp <= ts) {
        int rv = ngtcp2_conn_handle_expiry(c->conn, ts);
        if (rv != 0) {
            ps_notice("quic timer: %s", ngtcp2_strerror(rv));
            c->dead = 1;
            return kill_conn(c, 1);
        }
    }
    c->need_write = 0;
    uint8_t bufs[QUIC_BURST][1500];
    uint16_t lens[QUIC_BURST];
    int nbuf = 0;
    int hit_cap = 1;
    for (int i = 0; i < QUIC_WRITE_MAX; i++) {
        int64_t sid = -1;
        const uint8_t *data = NULL;
        size_t datalen = 0;
        if (c->stream_ready && c->tx_sent < c->tx_len) {
            sid = c->stream_id;
            data = c->tx + c->tx_pos + c->tx_sent;
            datalen = c->tx_len - c->tx_sent;
        }
        ngtcp2_ssize accepted = -1;
        ngtcp2_ssize nwrite =
            ngtcp2_conn_write_stream(c->conn, NULL, NULL, bufs[nbuf], sizeof(bufs[nbuf]), &accepted,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, sid, data, datalen, ts);
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            accepted = -1;
            nwrite = ngtcp2_conn_write_stream(c->conn, NULL, NULL, bufs[nbuf], sizeof(bufs[nbuf]),
                                              &accepted, NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0,
                                              ts);
        }
        if (nwrite == 0) {
            hit_cap = 0;
            break;
        }
        if (nwrite < 0) {
            ps_notice("quic write: %s", ngtcp2_strerror((int)nwrite));
            c->dead = 1;
            return kill_conn(c, 1);
        }
        if ((size_t)nwrite > sizeof(bufs[nbuf])) {
            c->dead = 1;
            return kill_conn(c, 1);
        }
        if (accepted > 0)
            c->tx_sent += (size_t)accepted;
        ngtcp2_conn_update_pkt_tx_time(c->conn, ts);
        lens[nbuf++] = (uint16_t)nwrite;
        if (nbuf == QUIC_BURST) {
            int rc = emit_bufs(c, fd, bufs, lens, nbuf);
            if (rc < 0) {
                c->dead = 1;
                return kill_conn(c, 1);
            }
            nbuf = 0;
            if (rc > 0)
                return 1;
        }
    }
    if (nbuf > 0) {
        int rc = emit_bufs(c, fd, bufs, lens, nbuf);
        if (rc < 0) {
            c->dead = 1;
            return kill_conn(c, 1);
        }
        if (rc > 0)
            return 1;
    }
    if (hit_cap)
        c->need_write = 1;
    return 0;
}

static int cid_eq(const ngtcp2_cid *cid, const uint8_t *data, size_t len)
{
    return cid->datalen == len && memcmp(cid->data, data, len) == 0;
}

/* ngtcp2 1.23 renamed this. 1.22, which EPEL 9 ships, still has the old name
   with the same NULL-means-count behavior. */
static size_t conn_scids(ngtcp2_conn *conn, ngtcp2_cid *dest)
{
#if NGTCP2_VERSION_NUM >= 0x011700
    return ngtcp2_conn_get_scid2(conn, dest);
#else
    return ngtcp2_conn_get_scid(conn, dest);
#endif
}

static int conn_matches(struct qconn *c, const uint8_t *dcid, size_t dcidlen)
{
    if (!c->used || !c->conn || c->dead)
        return 0;
    if (c->have_odcid && cid_eq(&c->original_dcid, dcid, dcidlen))
        return 1;
    ngtcp2_cid scids[8];
    size_t n = conn_scids(c->conn, NULL);
    if (n > 8)
        n = 8;
    if (n == 0)
        return 0;
    n = conn_scids(c->conn, scids);
    if (n > 8)
        n = 8;
    for (size_t i = 0; i < n; i++) {
        if (cid_eq(&scids[i], dcid, dcidlen))
            return 1;
    }
    return 0;
}

static struct qconn *find_dcid(struct ps_quic *q, const uint8_t *dcid, size_t dcidlen)
{
    for (unsigned i = 0; i < q->max_lanes; i++) {
        if (conn_matches(&q->conns[i], dcid, dcidlen))
            return &q->conns[i];
    }
    return NULL;
}

static struct qconn *alloc_slot(struct ps_quic *q)
{
    for (unsigned i = 0; i < q->max_lanes; i++) {
        if (!q->conns[i].used)
            return &q->conns[i];
    }
    return NULL;
}

static struct qconn *by_lane(const struct ps_quic *q, uint32_t lane)
{
    for (unsigned i = 0; i < q->max_lanes; i++) {
        const struct qconn *c = &q->conns[i];
        if (c->used && c->bound && !c->dead && c->lane == lane)
            return (struct qconn *)c;
    }
    return NULL;
}

static int read_into(struct qconn *c, const ngtcp2_path *path, const uint8_t *pkt, size_t pktlen,
                     ngtcp2_tstamp ts)
{
    int rv = ngtcp2_conn_read_pkt(c->conn, path, NULL, pkt, pktlen, ts);
    if (rv == 0 || rv == NGTCP2_ERR_RETRY)
        return 0;
    if (rv == NGTCP2_ERR_DROP_CONN) {
        ps_log("quic drop unbound=%d", c->bound ? 0 : 1);
        return kill_conn(c, 1);
    }
    ps_notice("quic read: %s", ngtcp2_strerror(rv));
    ngtcp2_ccerr ccerr;
    ngtcp2_ccerr_default(&ccerr);
    ngtcp2_ccerr_set_liberr(&ccerr, rv, NULL, 0);
    uint8_t buf[1500];
    ngtcp2_ssize n = ngtcp2_conn_write_connection_close(c->conn, NULL, NULL, buf, sizeof(buf),
                                                        &ccerr, ts);
    if (n > 0) {
        int fd = c->fd >= 0 ? c->fd : c->parent->fd;
        if (fd >= 0)
            send_udp(c, fd, buf, (size_t)n);
    }
    c->dead = 1;
    return kill_conn(c, 1);
}

static int accept_server(struct ps_quic *q, const uint8_t *pkt, size_t pktlen,
                         const struct sockaddr *peer, socklen_t peer_len, ngtcp2_tstamp ts)
{
    ngtcp2_pkt_hd hd;
    if (ngtcp2_accept(&hd, pkt, pktlen) != 0)
        return 0;
    if (!ngtcp2_is_supported_version(hd.version))
        return 0;
    struct qconn *c = alloc_slot(q);
    if (!c)
        return 0;
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->parent = q;
    c->used = 1;
    c->is_server = 1;
    c->have_odcid = 1;
    c->original_dcid = hd.dcid;
    if (conn_buffers(c) != 0) {
        conn_clear(c);
        return 0;
    }
    struct sockaddr_storage local;
    socklen_t llen = sizeof(local);
    if (getsockname(q->fd, (struct sockaddr *)&local, &llen) != 0) {
        conn_clear(c);
        return 0;
    }
    memcpy(&c->local, &local, llen);
    c->local_len = llen;
    memcpy(&c->remote, peer, peer_len);
    c->remote_len = peer_len;
    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(&path, (const ngtcp2_sockaddr *)&c->local, c->local_len,
                             (const ngtcp2_sockaddr *)&c->remote, c->remote_len, NULL);
    ngtcp2_cid scid;
    if (random_cid(&scid) != 0) {
        conn_clear(c);
        return 0;
    }
    ngtcp2_callbacks cb;
    fill_callbacks(&cb, 1);
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    tune_settings(&settings, ts);
    ngtcp2_transport_params params;
    fill_params(&params);
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;
    if (ngtcp2_conn_server_new(&c->conn, &hd.scid, &scid, &path.path, hd.version, &cb, &settings,
                               &params, NULL, c) != 0) {
        conn_clear(c);
        return 0;
    }
    if (conn_tls(c, q->ctx, NULL) != 0) {
        conn_clear(c);
        return 0;
    }
    return read_into(c, &path.path, pkt, pktlen, ts);
}

static int feed_packet(struct ps_quic *q, struct qconn *hint, const uint8_t *pkt, size_t pktlen,
                       const struct sockaddr *peer, socklen_t peer_len, ngtcp2_tstamp ts)
{
    ngtcp2_version_cid vc;
    struct qconn *c = hint;
    if (!c) {
        if (ngtcp2_pkt_decode_version_cid(&vc, pkt, pktlen, QUIC_CIDLEN) != 0)
            return 0;
        c = find_dcid(q, vc.dcid, vc.dcidlen);
        if (!c)
            return accept_server(q, pkt, pktlen, peer, peer_len, ts);
    }
    if (c->remote_len != peer_len || memcmp(&c->remote, peer, peer_len) != 0) {
        memcpy(&c->remote, peer, peer_len);
        c->remote_len = peer_len;
    }
    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(&path, (const ngtcp2_sockaddr *)&c->local, c->local_len,
                             (const ngtcp2_sockaddr *)&c->remote, c->remote_len, NULL);
    return read_into(c, &path.path, pkt, pktlen, ts);
}

static int pump_one(struct ps_quic *q, struct qconn *hint, const uint8_t *buf, size_t n,
                    const struct sockaddr *peer, socklen_t plen, ngtcp2_tstamp ts)
{
    if (n == 0)
        return 0;
    int rc = feed_packet(q, hint, buf, n, peer, plen, ts);
    if (rc < 0)
        return -1;
    if (hint && !hint->used)
        return 1;
    return 0;
}

static int pump_fd(struct ps_quic *q, struct qconn *hint, int fd, ngtcp2_tstamp ts)
{
#if defined(__linux__)
    uint8_t bufs[QUIC_BURST][2048];
    struct mmsghdr msgs[QUIC_BURST];
    struct iovec iov[QUIC_BURST];
    struct sockaddr_storage peers[QUIC_BURST];
    for (;;) {
        memset(msgs, 0, sizeof(msgs));
        for (int i = 0; i < QUIC_BURST; i++) {
            iov[i].iov_base = bufs[i];
            iov[i].iov_len = sizeof(bufs[i]);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = &peers[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(peers[i]);
        }
        int n = recvmmsg(fd, msgs, QUIC_BURST, 0, NULL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (hint) {
                hint->dead = 1;
                return kill_conn(hint, 1);
            }
            return -1;
        }
        for (int i = 0; i < n; i++) {
            int rc = pump_one(q, hint, bufs[i], msgs[i].msg_len, (struct sockaddr *)&peers[i],
                              msgs[i].msg_hdr.msg_namelen, ts);
            if (rc < 0)
                return -1;
            if (rc > 0)
                return 0;
        }
        if (n < QUIC_BURST)
            return 0;
    }
#else
    uint8_t buf[65535];
    for (;;) {
        struct sockaddr_storage peer;
        socklen_t plen = sizeof(peer);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (hint) {
                hint->dead = 1;
                return kill_conn(hint, 1);
            }
            return -1;
        }
        int rc = pump_one(q, hint, buf, (size_t)n, (struct sockaddr *)&peer, plen, ts);
        if (rc < 0)
            return -1;
        if (rc > 0)
            return 0;
    }
#endif
}

int ps_quic_available(void)
{
    return 1;
}

struct ps_quic *ps_quic_open(const struct ps_quic_cfg *cfg, uint16_t *listen_port)
{
    if (!cfg || !cfg->tls || cfg->max_lanes < 1 || cfg->max_lanes > PS_QUIC_MAX_LANES)
        return NULL;
    if (cfg->is_server && (!cfg->tls->cert_file || !cfg->tls->key_file))
        return NULL;
    ngtcp2_crypto_ossl_init();
    struct ps_quic *q = (struct ps_quic *)calloc(1, sizeof(*q));
    if (!q)
        return NULL;
    q->fd = -1;
    q->is_server = cfg->is_server ? 1 : 0;
    q->max_lanes = cfg->max_lanes;
    for (unsigned i = 0; i < PS_QUIC_MAX_LANES; i++)
        q->conns[i].fd = -1;
    if (cfg->tls->server_name)
        q->server_name = strdup(cfg->tls->server_name);
    q->ctx = q->is_server ? ps_tls_server_ctx(cfg->tls) : ps_tls_client_ctx(cfg->tls);
    if (!q->ctx || (cfg->tls->server_name && !q->server_name && cfg->tls->server_name[0])) {
        ps_quic_close(q);
        return NULL;
    }
    if (q->is_server) {
        SSL_CTX_set_alpn_select_cb(q->ctx, alpn_select, NULL);
        struct sockaddr_storage local;
        socklen_t llen = 0;
        const struct sockaddr *bind_addr = NULL;
        if (cfg->bind_addr && cfg->bind_len > 0 && cfg->bind_len <= sizeof(local)) {
            memcpy(&local, cfg->bind_addr, cfg->bind_len);
            llen = cfg->bind_len;
            if (ps_addr_set_port((struct sockaddr *)&local, llen, 0) != 0) {
                ps_quic_close(q);
                return NULL;
            }
            bind_addr = (struct sockaddr *)&local;
        }
        int family = bind_addr ? bind_addr->sa_family : AF_INET;
        int fd = udp_socket(family);
        if (fd < 0) {
            ps_quic_close(q);
            return NULL;
        }
        struct sockaddr_in any;
        if (!bind_addr) {
            memset(&any, 0, sizeof(any));
            any.sin_family = AF_INET;
            any.sin_addr.s_addr = htonl(INADDR_ANY);
            any.sin_port = 0;
            bind_addr = (struct sockaddr *)&any;
            llen = sizeof(any);
        }
        if (bind(fd, bind_addr, llen) != 0) {
            close(fd);
            ps_quic_close(q);
            return NULL;
        }
        struct sockaddr_storage bound;
        socklen_t blen = sizeof(bound);
        if (getsockname(fd, (struct sockaddr *)&bound, &blen) != 0) {
            close(fd);
            ps_quic_close(q);
            return NULL;
        }
        uint16_t port = 0;
        if (bound.ss_family == AF_INET)
            port = ntohs(((struct sockaddr_in *)&bound)->sin_port);
        else if (bound.ss_family == AF_INET6)
            port = ntohs(((struct sockaddr_in6 *)&bound)->sin6_port);
        if (port == 0) {
            close(fd);
            ps_quic_close(q);
            return NULL;
        }
        q->fd = fd;
        if (listen_port)
            *listen_port = port;
    }
    return q;
}

void ps_quic_close(struct ps_quic *quic)
{
    if (!quic)
        return;
    for (unsigned i = 0; i < PS_QUIC_MAX_LANES; i++) {
        quic->conns[i].parent = quic;
        conn_clear(&quic->conns[i]);
    }
    if (quic->fd >= 0)
        close(quic->fd);
    if (quic->ctx)
        SSL_CTX_free(quic->ctx);
    free(quic->server_name);
    free(quic);
}

int ps_quic_fds(struct ps_quic *quic, int *fds, int max)
{
    if (!quic || !fds || max <= 0)
        return 0;
    if (quic->is_server) {
        if (quic->fd < 0)
            return 0;
        fds[0] = quic->fd;
        return 1;
    }
    int n = 0;
    for (unsigned i = 0; i < quic->max_lanes && n < max; i++) {
        if (quic->conns[i].used && quic->conns[i].fd >= 0)
            fds[n++] = quic->conns[i].fd;
    }
    return n;
}

int ps_quic_wants_write(const struct ps_quic *quic)
{
    if (!quic)
        return 0;
    for (unsigned i = 0; i < quic->max_lanes; i++) {
        const struct qconn *c = &quic->conns[i];
        if (!c->used || c->dead)
            continue;
        if (c->pending_off < c->pending_n || c->need_write)
            return 1;
    }
    return 0;
}

int ps_quic_progress(struct ps_quic *quic)
{
    if (!quic)
        return -1;
    ngtcp2_tstamp ts = qnow();
    if (quic->is_server) {
        if (quic->fd >= 0 && pump_fd(quic, NULL, quic->fd, ts) < 0 && quic->broken)
            return -1;
    } else {
        for (unsigned i = 0; i < quic->max_lanes; i++) {
            struct qconn *c = &quic->conns[i];
            if (!c->used || c->fd < 0)
                continue;
            if (pump_fd(quic, c, c->fd, ts) < 0 && quic->broken)
                return -1;
        }
    }
    for (unsigned i = 0; i < quic->max_lanes; i++) {
        struct qconn *c = &quic->conns[i];
        if (!c->used)
            continue;
        if (c->dead) {
            if (kill_conn(c, 1) < 0)
                return -1;
            continue;
        }
        int fd = c->fd >= 0 ? c->fd : quic->fd;
        if (fd < 0)
            continue;
        if (write_conn(c, fd, ts) < 0 && quic->broken)
            return -1;
    }
    return quic->broken ? -1 : 0;
}

int ps_quic_connect(struct ps_quic *quic, uint32_t lane, const struct sockaddr *peer,
                    socklen_t peer_len)
{
    if (!quic || quic->is_server || !peer || peer_len == 0 || lane >= quic->max_lanes)
        return -1;
    if (quic->conns[lane].used)
        return -1;
    struct qconn *c = &quic->conns[lane];
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->parent = quic;
    c->used = 1;
    c->bound = 1;
    c->lane = lane;
    c->is_server = 0;
    c->connected = 1;
    if (conn_buffers(c) != 0) {
        conn_clear(c);
        return -1;
    }
    int fd = udp_socket(peer->sa_family);
    if (fd < 0) {
        conn_clear(c);
        return -1;
    }
    struct sockaddr_storage any;
    memset(&any, 0, sizeof(any));
    socklen_t any_len = 0;
    if (peer->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&any;
        in->sin_family = AF_INET;
        in->sin_addr.s_addr = htonl(INADDR_ANY);
        in->sin_port = 0;
        any_len = sizeof(*in);
    } else if (peer->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&any;
        in6->sin6_family = AF_INET6;
        in6->sin6_port = 0;
        any_len = sizeof(*in6);
    } else {
        close(fd);
        conn_clear(c);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&any, any_len) != 0 || connect(fd, peer, peer_len) != 0) {
        close(fd);
        conn_clear(c);
        return -1;
    }
    c->fd = fd;
    socklen_t llen = sizeof(c->local);
    if (getsockname(fd, (struct sockaddr *)&c->local, &llen) != 0) {
        conn_clear(c);
        return -1;
    }
    c->local_len = llen;
    memcpy(&c->remote, peer, peer_len);
    c->remote_len = peer_len;
    ngtcp2_cid dcid, scid;
    if (random_cid(&dcid) != 0 || random_cid(&scid) != 0) {
        conn_clear(c);
        return -1;
    }
    c->original_dcid = dcid;
    c->have_odcid = 1;
    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(&path, (const ngtcp2_sockaddr *)&c->local, c->local_len,
                             (const ngtcp2_sockaddr *)&c->remote, c->remote_len, NULL);
    ngtcp2_callbacks cb;
    fill_callbacks(&cb, 0);
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    tune_settings(&settings, qnow());
    ngtcp2_transport_params params;
    fill_params(&params);
    if (ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path.path, NGTCP2_PROTO_VER_V1, &cb,
                               &settings, &params, NULL, c) != 0) {
        conn_clear(c);
        return -1;
    }
    if (conn_tls(c, quic->ctx, quic->server_name) != 0) {
        conn_clear(c);
        return -1;
    }
    return 0;
}

int ps_quic_stream_ready(const struct ps_quic *quic, uint32_t lane)
{
    const struct qconn *c = quic ? by_lane(quic, lane) : NULL;
    return c && c->hs_done && c->stream_ready && !c->dead;
}

int ps_quic_send(struct ps_quic *quic, uint32_t lane, const void *data, size_t len,
                 size_t *accepted)
{
    if (accepted)
        *accepted = 0;
    struct qconn *c = quic ? by_lane(quic, lane) : NULL;
    if (!c || c->dead)
        return -1;
    if (!c->stream_ready || len == 0)
        return 1;
    if (!data)
        return -1;
    size_t room = c->tx_cap - (c->tx_pos + c->tx_len);
    if (room < len && c->tx_pos > 0) {
        memmove(c->tx, c->tx + c->tx_pos, c->tx_len);
        c->tx_pos = 0;
        room = c->tx_cap - c->tx_len;
    }
    size_t take = len < room ? len : room;
    if (take == 0)
        return 1;
    memcpy(c->tx + c->tx_pos + c->tx_len, data, take);
    c->tx_len += take;
    if (accepted)
        *accepted = take;
    return 0;
}

int ps_quic_recv(struct ps_quic *quic, uint32_t lane, void *dst, size_t cap, size_t *n)
{
    if (n)
        *n = 0;
    struct qconn *c = quic ? by_lane(quic, lane) : NULL;
    if (!c || c->dead)
        return -1;
    if (!dst || cap == 0 || c->rx_len == 0)
        return 0;
    size_t take = c->rx_len < cap ? c->rx_len : cap;
    memcpy(dst, c->rx, take);
    if (take < c->rx_len)
        memmove(c->rx, c->rx + take, c->rx_len - take);
    c->rx_len -= take;
    credit_read(c, take);
    if (n)
        *n = take;
    return 0;
}

int ps_quic_unbound(struct ps_quic *quic, unsigned *ids, int max)
{
    if (!quic || !ids || max <= 0)
        return 0;
    int n = 0;
    for (unsigned i = 0; i < quic->max_lanes && n < max; i++) {
        struct qconn *c = &quic->conns[i];
        if (c->used && !c->bound && !c->dead && c->rx_len > 0)
            ids[n++] = i;
    }
    return n;
}

size_t ps_quic_unbound_len(const struct ps_quic *quic, unsigned id)
{
    if (!quic || id >= quic->max_lanes)
        return 0;
    const struct qconn *c = &quic->conns[id];
    if (!c->used || c->bound || c->dead)
        return 0;
    return c->rx_len;
}

int ps_quic_unbound_copy(const struct ps_quic *quic, unsigned id, size_t off, void *dst, size_t n)
{
    if (!quic || id >= quic->max_lanes || !dst)
        return -1;
    const struct qconn *c = &quic->conns[id];
    if (!c->used || c->bound || c->dead || off + n > c->rx_len)
        return -1;
    memcpy(dst, c->rx + off, n);
    return 0;
}

int ps_quic_bind(struct ps_quic *quic, unsigned id, uint32_t lane)
{
    if (!quic || id >= quic->max_lanes)
        return -1;
    struct qconn *c = &quic->conns[id];
    if (!c->used || c->bound || c->dead)
        return -1;
    if (by_lane(quic, lane))
        return -1;
    c->bound = 1;
    c->lane = lane;
    return 0;
}

void ps_quic_drop(struct ps_quic *quic, unsigned id)
{
    if (!quic || id >= quic->max_lanes)
        return;
    struct qconn *c = &quic->conns[id];
    if (!c->used || c->bound)
        return;
    conn_clear(c);
}

static int export_conn(struct qconn *c, const uint8_t *context, size_t context_len, uint8_t out[32])
{
    if (!c || !c->used || c->dead || !c->ssl || !c->hs_done || !out)
        return -1;
    if (!SSL_is_init_finished(c->ssl))
        return -1;
    const char *label = SPT_QUIC_EXPORTER_LABEL;
    if (SSL_export_keying_material(c->ssl, out, 32, label, strlen(label), context, context_len,
                                   context ? 1 : 0) != 1)
        return -1;
    return 0;
}

int ps_quic_exporter(struct ps_quic *quic, uint32_t lane, const uint8_t *context,
                     size_t context_len, uint8_t out[32])
{
    return export_conn(by_lane(quic, lane), context, context_len, out);
}

int ps_quic_exporter_unbound(struct ps_quic *quic, unsigned id, const uint8_t *context,
                             size_t context_len, uint8_t out[32])
{
    if (!quic || id >= quic->max_lanes)
        return -1;
    struct qconn *c = &quic->conns[id];
    if (!c->used || c->bound)
        return -1;
    return export_conn(c, context, context_len, out);
}

int ps_quic_next_timeout_ms(const struct ps_quic *quic)
{
    if (!quic)
        return 1000;
    ngtcp2_tstamp now = qnow();
    ngtcp2_tstamp next = UINT64_MAX;
    for (unsigned i = 0; i < quic->max_lanes; i++) {
        const struct qconn *c = &quic->conns[i];
        if (!c->used || !c->conn || c->dead)
            continue;
        ngtcp2_tstamp exp = ngtcp2_conn_get_expiry(c->conn);
        if (exp < next)
            next = exp;
    }
    if (next == UINT64_MAX)
        return 1000;
    if (next <= now)
        return 0;
    uint64_t ms = (next - now) / NGTCP2_MILLISECONDS;
    if (ms == 0)
        ms = 1;
    if (ms > 1000)
        ms = 1000;
    return (int)ms;
}

int ps_quic_supported(void)
{
    return 1;
}

#else

int ps_quic_available(void)
{
    return 0;
}

struct ps_quic *ps_quic_open(const struct ps_quic_cfg *cfg, uint16_t *listen_port)
{
    (void)cfg;
    (void)listen_port;
    return NULL;
}

void ps_quic_close(struct ps_quic *quic)
{
    (void)quic;
}

int ps_quic_fds(struct ps_quic *quic, int *fds, int max)
{
    (void)quic;
    (void)fds;
    (void)max;
    return 0;
}

int ps_quic_wants_write(const struct ps_quic *quic)
{
    (void)quic;
    return 0;
}

int ps_quic_progress(struct ps_quic *quic)
{
    (void)quic;
    return -1;
}

int ps_quic_connect(struct ps_quic *quic, uint32_t lane, const struct sockaddr *peer,
                    socklen_t peer_len)
{
    (void)quic;
    (void)lane;
    (void)peer;
    (void)peer_len;
    return -1;
}

int ps_quic_stream_ready(const struct ps_quic *quic, uint32_t lane)
{
    (void)quic;
    (void)lane;
    return 0;
}

int ps_quic_send(struct ps_quic *quic, uint32_t lane, const void *data, size_t len, size_t *accepted)
{
    (void)quic;
    (void)lane;
    (void)data;
    (void)len;
    if (accepted)
        *accepted = 0;
    return -1;
}

int ps_quic_recv(struct ps_quic *quic, uint32_t lane, void *dst, size_t cap, size_t *n)
{
    (void)quic;
    (void)lane;
    (void)dst;
    (void)cap;
    if (n)
        *n = 0;
    return -1;
}

int ps_quic_unbound(struct ps_quic *quic, unsigned *ids, int max)
{
    (void)quic;
    (void)ids;
    (void)max;
    return 0;
}

size_t ps_quic_unbound_len(const struct ps_quic *quic, unsigned id)
{
    (void)quic;
    (void)id;
    return 0;
}

int ps_quic_unbound_copy(const struct ps_quic *quic, unsigned id, size_t off, void *dst, size_t n)
{
    (void)quic;
    (void)id;
    (void)off;
    (void)dst;
    (void)n;
    return -1;
}

int ps_quic_bind(struct ps_quic *quic, unsigned id, uint32_t lane)
{
    (void)quic;
    (void)id;
    (void)lane;
    return -1;
}

void ps_quic_drop(struct ps_quic *quic, unsigned id)
{
    (void)quic;
    (void)id;
}

int ps_quic_exporter(struct ps_quic *quic, uint32_t lane, const uint8_t *context,
                     size_t context_len, uint8_t out[32])
{
    (void)quic;
    (void)lane;
    (void)context;
    (void)context_len;
    (void)out;
    return -1;
}

int ps_quic_exporter_unbound(struct ps_quic *quic, unsigned id, const uint8_t *context,
                             size_t context_len, uint8_t out[32])
{
    (void)quic;
    (void)id;
    (void)context;
    (void)context_len;
    (void)out;
    return -1;
}

int ps_quic_next_timeout_ms(const struct ps_quic *quic)
{
    (void)quic;
    return 1000;
}

int ps_quic_supported(void)
{
    return 0;
}

#endif
