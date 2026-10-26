#include "parsock.h"

#include <errno.h>
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
    fprintf(stderr, "fail: transfer timed out\n");
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
        sa->rc = 1;
        ps_listener_close(ln);
        return NULL;
    }
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
    int rekey_at;
    int rc;
};

static void *send_main(void *arg)
{
    struct xfer *x = (struct xfer *)arg;
    uint8_t buf[8192];
    size_t off = 0;
    int rekeyed = 0;
    while (off < x->total) {
        if (!rekeyed && x->rekey_at >= 0 && off >= (size_t)x->rekey_at) {
            if (ps_rekey(x->conn) != 0) {
                fprintf(stderr, "rekey %s\n", ps_strerror(ps_connection_error(x->conn)));
                x->rc = 1;
                return NULL;
            }
            rekeyed = 1;
        }
        size_t chunk = sizeof(buf);
        if (chunk > x->total - off)
            chunk = x->total - off;
        for (size_t i = 0; i < chunk; i++)
            buf[i] = pattern(off + i);
        ssize_t n = ps_send(x->conn, buf, chunk);
        if (n <= 0) {
            fprintf(stderr, "client send %s\n", ps_strerror(ps_connection_error(x->conn)));
            x->rc = 1;
            return NULL;
        }
        off += (size_t)n;
    }
    if (ps_shutdown(x->conn, SHUT_WR) != 0)
        x->rc = 1;
    return NULL;
}

static void *recv_main(void *arg)
{
    struct xfer *x = (struct xfer *)arg;
    uint8_t buf[8192];
    size_t off = 0;
    while (off < x->total) {
        ssize_t n = ps_recv(x->conn, buf, sizeof(buf));
        if (n <= 0) {
            fprintf(stderr, "client recv %s at %zu\n", ps_strerror(ps_connection_error(x->conn)), off);
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

static int run_case(const char *name, const char *cert, const char *key, const struct ps_options *base,
                    size_t nbytes, int rekey_at, unsigned expect_sockets)
{
    fprintf(stderr, "case %s\n", name);
    struct server_arg sa;
    memset(&sa, 0, sizeof(sa));
    sa.opt = *base;
    pthread_mutex_init(&sa.mu, NULL);
    pthread_cond_init(&sa.cv, NULL);
    pthread_t thr;
    if (pthread_create(&thr, NULL, server_main, &sa) != 0)
        return 1;
    pthread_mutex_lock(&sa.mu);
    while (!sa.ready)
        pthread_cond_wait(&sa.cv, &sa.mu);
    uint16_t port = sa.port;
    int ready = sa.ready;
    pthread_mutex_unlock(&sa.mu);
    if (ready < 0) {
        pthread_join(thr, NULL);
        fprintf(stderr, "%s: listen failed\n", name);
        return 1;
    }
    ps_connection_t *conn = ps_connect("127.0.0.1", port, base);
    if (!conn) {
        fprintf(stderr, "%s: connect failed\n", name);
        fails++;
        pthread_mutex_lock(&sa.mu);
        sa.client_done = 1;
        pthread_cond_signal(&sa.cv);
        pthread_mutex_unlock(&sa.mu);
        pthread_join(thr, NULL);
        return 1;
    }
    struct ps_stats st;
    if (ps_connection_stats(conn, &st) == 0 && expect_sockets)
        expect(st.active_sockets == expect_sockets, name);
    struct xfer x;
    memset(&x, 0, sizeof(x));
    x.conn = conn;
    x.total = nbytes;
    x.rekey_at = rekey_at;
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
        fprintf(stderr, "%s: server failed\n", name);
        fails++;
    }
    pthread_mutex_destroy(&sa.mu);
    pthread_cond_destroy(&sa.cv);
    (void)cert;
    (void)key;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: test_transfer cert key\n");
        return 2;
    }
    signal(SIGALRM, on_alarm);
    alarm(45);
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
    opt.min_sockets = 4;
    opt.max_sockets = 4;
    opt.initial_sockets = 4;
    opt.worker_threads = 0;
    opt.frame_size = 16384;
    opt.receive_window = 65536;
    opt.io_timeout_ms = 15000;
    opt.connect_timeout_ms = 10000;
    run_case("aes-inline", argv[1], argv[2], &opt, 256 * 1024, -1, 4);

    opt.worker_threads = 2;
    run_case("aes-workers", argv[1], argv[2], &opt, 256 * 1024, -1, 4);

    opt.worker_threads = 0;
    opt.aead = PS_AEAD_CHACHA20_POLY1305;
    run_case("chacha", argv[1], argv[2], &opt, 128 * 1024, -1, 4);

    opt.aead = PS_AEAD_AES_256_GCM;
    run_case("rekey", argv[1], argv[2], &opt, 128 * 1024, 32 * 1024, 4);

    opt.scale_mode = PS_SCALE_AUTO;
    opt.min_sockets = 1;
    opt.max_sockets = 4;
    opt.initial_sockets = 2;
    opt.receive_window = 1ull << 20;
    opt.scale_interval_ms = 200;
    run_case("auto", argv[1], argv[2], &opt, 64 * 1024, -1, 0);

    alarm(0);
    if (fails) {
        fprintf(stderr, "%d transfer checks failed\n", fails);
        return 1;
    }
    return 0;
}
