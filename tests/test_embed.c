#include "parsock.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
    fprintf(stderr, "fail: embed timed out\n");
    _exit(2);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint8_t pattern(size_t off)
{
    return (uint8_t)((off * 131u) ^ (off >> 8));
}

static int listen_port(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &sl) != 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

struct side {
    ps_session_t *session;
    int wake[2];
    int data_fd;
};

static void poke(void *ctx)
{
    struct side *s = (struct side *)ctx;
    char b = 1;
    ssize_t n = write(s->wake[1], &b, 1);
    (void)n;
}

static void want_io(void *ctx, int fd, int rd, int wr)
{
    (void)fd;
    (void)rd;
    (void)wr;
    poke(ctx);
}

static int drive(struct side *s, uint64_t deadline, size_t *sent, size_t *got, const uint8_t *tx,
                 size_t tx_len, uint8_t *rx, size_t rx_len, int echo)
{
    uint8_t echo_buf[65536];
    size_t echo_len = 0;
    size_t echo_off = 0;
    size_t echoed = 0;
    int write_closed = 0;
    int read_done = 0;
    while (now_ms() < deadline) {
        if (ps_session_state(s->session) == PS_STATE_FAILED) {
            fprintf(stderr, "session failed: %s\n", ps_strerror(ps_session_error(s->session)));
            return -1;
        }
        ps_embed_service(s->session);
        if (ps_session_state(s->session) == PS_STATE_OPEN && tx && sent && *sent < tx_len) {
            size_t acc = 0;
            int rc = ps_submit_send(s->session, tx + *sent, tx_len - *sent, &acc);
            if (rc == 0)
                *sent += acc;
            else if (rc != -PS_ERR_AGAIN && rc != -PS_ERR_FLOW)
                return -1;
        } else if (tx && sent && *sent == tx_len && !write_closed) {
            ps_embed_shutdown_write(s->session);
            write_closed = 1;
        }
        if (rx && got && !read_done) {
            size_t n = 0;
            int rc = ps_submit_recv(s->session, rx + *got, rx_len - *got, &n);
            if (rc == 0 && n == 0)
                read_done = 1;
            else if (rc == 0)
                *got += n;
            else if (rc != -PS_ERR_AGAIN)
                return -1;
        }
        if (echo) {
            if (echo_off > 0 && (echo_off == echo_len || echo_len == sizeof(echo_buf))) {
                memmove(echo_buf, echo_buf + echo_off, echo_len - echo_off);
                echo_len -= echo_off;
                echo_off = 0;
            }
            if (echo_off < echo_len) {
                size_t acc = 0;
                int rc = ps_submit_send(s->session, echo_buf + echo_off, echo_len - echo_off, &acc);
                if (rc == 0) {
                    echo_off += acc;
                    echoed += acc;
                }
            }
            if (echo_len < sizeof(echo_buf)) {
                size_t n = 0;
                int rc = ps_submit_recv(s->session, echo_buf + echo_len, sizeof(echo_buf) - echo_len, &n);
                if (rc == 0 && n == 0 && echo_off == echo_len &&
                    ps_session_state(s->session) == PS_STATE_OPEN) {
                    if (!write_closed)
                        ps_embed_shutdown_write(s->session);
                    write_closed = 1;
                } else if (rc == 0) {
                    echo_len += n;
                } else if (rc != -PS_ERR_AGAIN) {
                    return -1;
                }
            }
            if (got)
                *got = echoed;
            if (write_closed && echo_off == echo_len) {
                struct ps_watch left[PS_MAX_SUBFLOWS + 2];
                int ln = ps_session_watches(s->session, left, PS_MAX_SUBFLOWS + 2);
                int busy = 0;
                for (int i = 0; i < ln; i++) {
                    if (left[i].want_write)
                        busy = 1;
                }
                if (!busy)
                    return 0;
            }
        }
        if (read_done && write_closed)
            return 0;
        struct ps_watch watches[PS_MAX_SUBFLOWS + 2];
        int nw = ps_session_watches(s->session, watches, PS_MAX_SUBFLOWS + 2);
        struct pollfd pfds[PS_MAX_SUBFLOWS + 4];
        int np = 0;
        pfds[np].fd = s->wake[0];
        pfds[np].events = POLLIN;
        pfds[np].revents = 0;
        np++;
        int data_slot = -1;
        if (s->data_fd >= 0) {
            data_slot = np;
            pfds[np].fd = s->data_fd;
            pfds[np].events = POLLIN;
            pfds[np].revents = 0;
            np++;
        }
        int base = np;
        for (int i = 0; i < nw; i++) {
            pfds[np].fd = watches[i].fd;
            pfds[np].events = 0;
            if (watches[i].want_read)
                pfds[np].events |= POLLIN;
            if (watches[i].want_write)
                pfds[np].events |= POLLOUT;
            pfds[np].revents = 0;
            np++;
        }
        for (int i = 0; i < nw; i++) {
            if (watches[i].want_write)
                ps_on_writable(s->session, watches[i].fd);
            if (watches[i].want_read)
                ps_on_readable(s->session, watches[i].fd);
        }
        nw = ps_session_watches(s->session, watches, PS_MAX_SUBFLOWS + 2);
        np = 1;
        data_slot = -1;
        if (s->data_fd >= 0) {
            data_slot = np;
            pfds[np].fd = s->data_fd;
            pfds[np].events = POLLIN;
            pfds[np].revents = 0;
            np++;
        }
        base = np;
        for (int i = 0; i < nw; i++) {
            pfds[np].fd = watches[i].fd;
            pfds[np].events = 0;
            if (watches[i].want_read)
                pfds[np].events |= POLLIN;
            if (watches[i].want_write)
                pfds[np].events |= POLLOUT;
            pfds[np].revents = 0;
            np++;
        }
        int pr = poll(pfds, (nfds_t)np, 50);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pfds[0].revents & POLLIN) {
            char buf[32];
            while (read(s->wake[0], buf, sizeof(buf)) > 0) {
            }
        }
        if (data_slot >= 0 && (pfds[data_slot].revents & POLLIN)) {
            int fd = accept(s->data_fd, NULL, NULL);
            if (fd >= 0) {
                uint8_t sid[32];
                uint32_t id = 0;
                if (ps_preface_read(fd, sid, &id, 2000) != 0 ||
                    ps_embed_adopt_subflow(s->session, id, fd) != 0)
                    close(fd);
            }
        }
        for (int i = 0; i < nw; i++) {
            short ev = pfds[base + i].revents;
            if (ev & (POLLIN | POLLERR | POLLHUP | POLLNVAL))
                ps_on_readable(s->session, watches[i].fd);
            if (ev & POLLOUT)
                ps_on_writable(s->session, watches[i].fd);
        }
    }
    fprintf(stderr, "embed deadline state=%d err=%s sent=%zu got=%zu\n",
            ps_session_state(s->session), ps_strerror(ps_session_error(s->session)),
            sent ? *sent : 0, got ? *got : 0);
    return -1;
}

struct ready {
    uint16_t cport;
    uint16_t dport;
    int go;
    int client_done;
    pthread_mutex_t mu;
    pthread_cond_t cv;
};

struct srv {
    struct ready *ready;
    struct ps_options opt;
    int rc;
    size_t echoed;
};

static void *server_thread(void *arg)
{
    struct srv *sv = (struct srv *)arg;
    uint16_t cport = 0, dport = 0;
    int cfd = listen_port(&cport);
    int dfd = listen_port(&dport);
    if (cfd < 0 || dfd < 0) {
        sv->rc = 1;
        return NULL;
    }
    struct side side;
    memset(&side, 0, sizeof(side));
    side.data_fd = dfd;
    if (pipe(side.wake) != 0) {
        sv->rc = 1;
        return NULL;
    }
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(side.wake[i], F_GETFL, 0);
        if (flags >= 0)
            fcntl(side.wake[i], F_SETFL, flags | O_NONBLOCK);
    }
    ps_io_cbs cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.ctx = &side;
    cbs.poke = poke;
    cbs.want_io = want_io;
    side.session = ps_embed_create(1, &sv->opt, &cbs);
    if (!side.session) {
        sv->rc = 1;
        return NULL;
    }
    pthread_mutex_lock(&sv->ready->mu);
    sv->ready->cport = cport;
    sv->ready->dport = dport;
    sv->ready->go = 1;
    pthread_cond_signal(&sv->ready->cv);
    pthread_mutex_unlock(&sv->ready->mu);
    int fd = accept(cfd, NULL, NULL);
    if (fd < 0) {
        sv->rc = 1;
        ps_embed_close(side.session);
        return NULL;
    }
    if (ps_embed_set_data_port(side.session, dport) != 0 || ps_embed_set_control(side.session, fd) != 0) {
        sv->rc = 1;
        close(fd);
        ps_embed_close(side.session);
        return NULL;
    }
    size_t got = 0;
    if (drive(&side, now_ms() + 15000, NULL, &got, NULL, 0, NULL, 0, 1) != 0)
        sv->rc = 1;
    sv->echoed = got;
    pthread_mutex_lock(&sv->ready->mu);
    while (!sv->ready->client_done)
        pthread_cond_wait(&sv->ready->cv, &sv->ready->mu);
    pthread_mutex_unlock(&sv->ready->mu);
    ps_embed_close(side.session);
    close(cfd);
    close(dfd);
    close(side.wake[0]);
    close(side.wake[1]);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: test_embed cert key\n");
        return 2;
    }
    signal(SIGALRM, on_alarm);
    alarm(30);
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
    opt.min_sockets = 2;
    opt.max_sockets = 2;
    opt.initial_sockets = 2;
    opt.worker_threads = 0;
    opt.frame_size = 16384;
    opt.receive_window = 65536;
    opt.io_timeout_ms = 10000;

    struct ready ready;
    memset(&ready, 0, sizeof(ready));
    pthread_mutex_init(&ready.mu, NULL);
    pthread_cond_init(&ready.cv, NULL);
    struct srv sv;
    memset(&sv, 0, sizeof(sv));
    sv.ready = &ready;
    sv.opt = opt;
    pthread_t thr;
    pthread_create(&thr, NULL, server_thread, &sv);
    pthread_mutex_lock(&ready.mu);
    while (!ready.go)
        pthread_cond_wait(&ready.cv, &ready.mu);
    uint16_t cport = ready.cport;
    pthread_mutex_unlock(&ready.mu);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cport);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "embed connect failed\n");
        return 1;
    }
    struct side side;
    memset(&side, 0, sizeof(side));
    side.data_fd = -1;
    if (pipe(side.wake) != 0)
        return 1;
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(side.wake[i], F_GETFL, 0);
        if (flags >= 0)
            fcntl(side.wake[i], F_SETFL, flags | O_NONBLOCK);
    }
    ps_io_cbs cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.ctx = &side;
    cbs.poke = poke;
    cbs.want_io = want_io;
    side.session = ps_embed_create(0, &opt, &cbs);
    expect(side.session != NULL, "client session");
    if (!side.session)
        return 1;
    expect(ps_embed_set_control(side.session, fd) == 0, "set control");
    enum { N = 96 * 1024 };
    uint8_t *tx = (uint8_t *)malloc(N);
    uint8_t *rx = (uint8_t *)malloc(N);
    for (size_t i = 0; i < N; i++)
        tx[i] = pattern(i);
    size_t sent = 0, got = 0;
    int rc = drive(&side, now_ms() + 15000, &sent, &got, tx, N, rx, N, 0);
    pthread_mutex_lock(&ready.mu);
    ready.client_done = 1;
    pthread_cond_signal(&ready.cv);
    pthread_mutex_unlock(&ready.mu);
    expect(rc == 0, "drive");
    expect(sent == N && got == N, "byte count");
    expect(got == N && memcmp(tx, rx, N) == 0, "bytes match");
    ps_embed_close(side.session);
    close(side.wake[0]);
    close(side.wake[1]);
    pthread_join(thr, NULL);
    expect(sv.rc == 0, "server");
    expect(sv.echoed == N, "echoed");
    free(tx);
    free(rx);
    alarm(0);
    if (fails) {
        fprintf(stderr, "%d embed checks failed\n", fails);
        return 1;
    }
    return 0;
}
