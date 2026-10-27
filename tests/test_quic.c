#include "parsock.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        fails++;
    }
}

static void on_alarm(int sig)
{
    (void)sig;
    fprintf(stderr, "fail: quic transfer timed out\n");
    _exit(2);
}

static uint8_t pattern(size_t off)
{
    return (uint8_t)((off * 131u) ^ (off >> 8));
}

struct server_arg {
    struct ps_options opt;
    uint16_t port;
    int ready;
    int rc;
    int client_done;
    pthread_mutex_t mu;
    pthread_cond_t cv;
};

static void *server_main(void *arg)
{
    struct server_arg *sa = (struct server_arg *)arg;
    ps_listener_t *ln = ps_listen("127.0.0.1", 0, &sa->opt);
    if (!ln) {
        sa->rc = 1;
        pthread_mutex_lock(&sa->mu);
        sa->ready = -1;
        pthread_cond_signal(&sa->cv);
        pthread_mutex_unlock(&sa->mu);
        return NULL;
    }
    uint16_t port = 0;
    ps_listener_port(ln, &port, NULL);
    pthread_mutex_lock(&sa->mu);
    sa->port = port;
    sa->ready = 1;
    pthread_cond_signal(&sa->cv);
    pthread_mutex_unlock(&sa->mu);
    ps_connection_t *conn = ps_accept(ln);
    if (!conn) {
        fprintf(stderr, "server accept %s\n", ps_strerror(ps_recent_error()));
        sa->rc = 1;
        ps_listener_close(ln);
        return NULL;
    }
    expect(ps_connection_transport(conn) == PS_TRANSPORT_QUIC, "server transport");
    uint8_t buf[16384];
    for (;;) {
        ssize_t n = ps_recv(conn, buf, sizeof(buf));
        if (n < 0) {
            fprintf(stderr, "server recv %s\n", ps_strerror(ps_connection_error(conn)));
            sa->rc = 1;
            break;
        }
        if (n == 0)
            break;
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = ps_send(conn, buf + off, (size_t)n - off);
            if (w <= 0) {
                fprintf(stderr, "server send %s\n", ps_strerror(ps_connection_error(conn)));
                sa->rc = 1;
                n = -1;
                break;
            }
            off += (size_t)w;
        }
        if (n < 0)
            break;
    }
    pthread_mutex_lock(&sa->mu);
    while (!sa->client_done)
        pthread_cond_wait(&sa->cv, &sa->mu);
    pthread_mutex_unlock(&sa->mu);
    ps_shutdown(conn, SHUT_WR);
    ps_close(conn);
    ps_listener_close(ln);
    return NULL;
}

struct xfer {
    ps_connection_t *conn;
    size_t total;
    int rc;
};

static void *send_main(void *arg)
{
    struct xfer *x = (struct xfer *)arg;
    uint8_t buf[8192];
    size_t off = 0;
    while (off < x->total) {
        size_t n = x->total - off;
        if (n > sizeof(buf))
            n = sizeof(buf);
        for (size_t i = 0; i < n; i++)
            buf[i] = pattern(off + i);
        ssize_t w = ps_send(x->conn, buf, n);
        if (w <= 0) {
            fprintf(stderr, "client send %s\n", ps_strerror(ps_connection_error(x->conn)));
            x->rc = 1;
            return NULL;
        }
        off += (size_t)w;
    }
    ps_shutdown(x->conn, SHUT_WR);
    return NULL;
}

static void *recv_main(void *arg)
{
    struct xfer *x = (struct xfer *)arg;
    uint8_t buf[8192];
    size_t off = 0;
    while (off < x->total) {
        ssize_t n = ps_recv(x->conn, buf, sizeof(buf));
        if (n < 0) {
            fprintf(stderr, "client recv %s\n", ps_strerror(ps_connection_error(x->conn)));
            x->rc = 1;
            return NULL;
        }
        if (n == 0) {
            fprintf(stderr, "client eof at %zu\n", off);
            x->rc = 1;
            return NULL;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != pattern(off + (size_t)i)) {
                fprintf(stderr, "mismatch at %zu\n", off + (size_t)i);
                x->rc = 1;
                return NULL;
            }
        }
        off += (size_t)n;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: test_quic cert key\n");
        return 2;
    }
    if (!ps_quic_supported()) {
        fprintf(stderr, "quic backend is not built; skip\n");
        return 0;
    }
    signal(SIGALRM, on_alarm);
    alarm(40);
    struct ps_tls_config tls;
    memset(&tls, 0, sizeof(tls));
    tls.cert_file = argv[1];
    tls.key_file = argv[2];
    tls.ca_file = argv[1];
    tls.server_name = "127.0.0.1";
    tls.verify_peer = 1;

    struct ps_options opt;
    ps_options_init(&opt);
    opt.tls = &tls;
    opt.transport = PS_TRANSPORT_QUIC;
    opt.allow_tcp_fallback = 0;
    opt.min_sockets = 4;
    opt.max_sockets = 4;
    opt.initial_sockets = 4;
    opt.worker_threads = 0;
    opt.frame_size = 16384;
    opt.receive_window = 1u << 20;
    opt.io_timeout_ms = 15000;
    opt.connect_timeout_ms = 10000;

    struct server_arg sa;
    memset(&sa, 0, sizeof(sa));
    sa.opt = opt;
    pthread_mutex_init(&sa.mu, NULL);
    pthread_cond_init(&sa.cv, NULL);
    pthread_t thr;
    pthread_create(&thr, NULL, server_main, &sa);
    pthread_mutex_lock(&sa.mu);
    while (!sa.ready)
        pthread_cond_wait(&sa.cv, &sa.mu);
    uint16_t port = sa.port;
    int ready = sa.ready;
    pthread_mutex_unlock(&sa.mu);
    if (ready < 0) {
        pthread_join(thr, NULL);
        fprintf(stderr, "listen failed\n");
        return 1;
    }
    ps_connection_t *conn = ps_connect("127.0.0.1", port, &opt);
    if (!conn) {
        fprintf(stderr, "connect failed %s\n", ps_strerror(ps_recent_error()));
        fails++;
        pthread_mutex_lock(&sa.mu);
        sa.client_done = 1;
        pthread_cond_signal(&sa.cv);
        pthread_mutex_unlock(&sa.mu);
        pthread_join(thr, NULL);
        return 1;
    }
    expect(ps_connection_transport(conn) == PS_TRANSPORT_QUIC, "client transport");
    struct ps_stats st;
    if (ps_connection_stats(conn, &st) == 0)
        expect(st.active_sockets == 4, "four quic lanes");
    struct xfer x;
    memset(&x, 0, sizeof(x));
    x.conn = conn;
    x.total = 256 * 1024;
    pthread_t ts, tr;
    pthread_create(&ts, NULL, send_main, &x);
    pthread_create(&tr, NULL, recv_main, &x);
    pthread_join(ts, NULL);
    pthread_join(tr, NULL);
    if (x.rc)
        fails++;
    pthread_mutex_lock(&sa.mu);
    sa.client_done = 1;
    pthread_cond_signal(&sa.cv);
    pthread_mutex_unlock(&sa.mu);
    ps_close(conn);
    pthread_join(thr, NULL);
    if (sa.rc) {
        fprintf(stderr, "server failed\n");
        fails++;
    }
    pthread_mutex_destroy(&sa.mu);
    pthread_cond_destroy(&sa.cv);
    if (fails) {
        fprintf(stderr, "%d quic checks failed\n", fails);
        return 1;
    }
    return 0;
}
