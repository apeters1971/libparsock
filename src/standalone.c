#include "session.h"

#include "log.h"
#include "net.h"
#include "spt_wire.h"
#include "tls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>

struct io_lane {
    struct ps_runtime *rt;
    int index;
    int wake_r;
    int wake_w;
    pthread_t thread;
};

struct ps_runtime {
    ps_session_t *session;
    struct ps_listener *listener;
    int nlanes;
    int stop;
    int started;
    struct io_lane *lanes;
};

struct map_node {
    uint8_t id[SPT_SESSION_ID_LEN];
    ps_session_t *session;
    struct map_node *next;
};

struct ps_listener {
    int cfd;
    int dfd;
    uint16_t cport;
    uint16_t dport;
    SSL_CTX *ctx;
    struct ps_options opt;
    struct ps_tls_config tls;
    char *cert;
    char *key;
    char *ca;
    char *sni;
    pthread_t data_thread;
    pthread_mutex_t mu;
    int stop;
    int data_started;
    struct map_node *map;
};

struct ps_connection {
    ps_session_t *session;
    struct ps_runtime *rt;
    uint32_t io_timeout_ms;
    uint32_t connect_timeout_ms;
};

static void rt_poke(void *ctx)
{
    struct ps_runtime *rt = (struct ps_runtime *)ctx;
    if (!rt || !rt->lanes)
        return;
    for (int i = 0; i < rt->nlanes; i++) {
        if (rt->lanes[i].wake_w < 0)
            continue;
        char byte = 1;
        ssize_t n = write(rt->lanes[i].wake_w, &byte, 1);
        (void)n;
    }
}

static void rt_poke_lane(struct ps_runtime *rt, int lane_idx)
{
    if (!rt || !rt->lanes || lane_idx < 0 || lane_idx >= rt->nlanes)
        return;
    if (rt->lanes[lane_idx].wake_w < 0)
        return;
    char byte = 1;
    ssize_t n = write(rt->lanes[lane_idx].wake_w, &byte, 1);
    (void)n;
}

static void rt_want(void *ctx, int fd, int want_read, int want_write)
{
    (void)want_read;
    (void)want_write;
    struct ps_runtime *rt = (struct ps_runtime *)ctx;
    if (!rt || rt->nlanes <= 0)
        return;
    if (fd < 0 || rt->nlanes == 1) {
        rt_poke(ctx);
        return;
    }
    int m = fd % rt->nlanes;
    if (m < 0)
        m += rt->nlanes;
    rt_poke_lane(rt, m);
}

static void listener_add(struct ps_listener *ln, const uint8_t id[32], ps_session_t *session)
{
    struct map_node *node = (struct map_node *)calloc(1, sizeof(*node));
    if (!node)
        return;
    memcpy(node->id, id, 32);
    node->session = session;
    pthread_mutex_lock(&ln->mu);
    node->next = ln->map;
    ln->map = node;
    ps_session_ref(session);
    pthread_mutex_unlock(&ln->mu);
}

static void listener_remove(struct ps_listener *ln, ps_session_t *session)
{
    if (!ln)
        return;
    pthread_mutex_lock(&ln->mu);
    struct map_node **link = &ln->map;
    while (*link) {
        if ((*link)->session == session) {
            struct map_node *dead = *link;
            *link = dead->next;
            pthread_mutex_unlock(&ln->mu);
            ps_session_unref(dead->session);
            free(dead);
            return;
        }
        link = &(*link)->next;
    }
    pthread_mutex_unlock(&ln->mu);
}

static ps_session_t *listener_find(struct ps_listener *ln, const uint8_t id[32])
{
    pthread_mutex_lock(&ln->mu);
    for (struct map_node *n = ln->map; n; n = n->next) {
        if (memcmp(n->id, id, 32) == 0) {
            ps_session_ref(n->session);
            pthread_mutex_unlock(&ln->mu);
            return n->session;
        }
    }
    pthread_mutex_unlock(&ln->mu);
    return NULL;
}

static void on_register(void *ctx, const uint8_t id[32], ps_session_t *session)
{
    struct ps_runtime *rt = (struct ps_runtime *)ctx;
    if (rt->listener)
        listener_add(rt->listener, id, session);
}

static void on_unregister(void *ctx, ps_session_t *session)
{
    struct ps_runtime *rt = (struct ps_runtime *)ctx;
    listener_remove(rt->listener, session);
}

static void drain_wake(int fd)
{
    char buf[64];
    while (read(fd, buf, sizeof(buf)) > 0) {
    }
}

static int lane_owns(const struct io_lane *lane, int fd)
{
    int n = lane->rt->nlanes;
    if (n <= 1)
        return 1;
    int m = fd % n;
    if (m < 0)
        m += n;
    return m == lane->index;
}

static void lane_fill(struct io_lane *lane, int *read_again)
{
    struct ps_runtime *rt = lane->rt;
    struct ps_watch watches[PS_MAX_SUBFLOWS + 2];
    int nw = ps_session_watches(rt->session, watches, PS_MAX_SUBFLOWS + 2);
    int again_left = 0;
    for (int i = 0; i < nw; i++) {
        if (!lane_owns(lane, watches[i].fd))
            continue;
        if (ps_session_is_control(rt->session, watches[i].fd))
            continue;
        int again = 0;
        if (ps_session_ingest(rt->session, watches[i].fd, &again) < 0)
            break;
        if (again)
            again_left = 1;
    }
    *read_again = again_left;
}

static void *runtime_main(void *arg)
{
    struct io_lane *lane = (struct io_lane *)arg;
    struct ps_runtime *rt = lane->rt;
    int read_again = 0;
    while (!rt->stop) {
        /* Opening and closing sockets is session-wide. One lane does it.
           poll waits until the kernel can take or produce bytes. A zero
           timeout spins every lane whenever a socket is writable, and that
           steals the cores the checksum workers need. */
        if (lane->index == 0)
            ps_embed_service(rt->session);
        if (ps_session_inline_pending(rt->session)) {
            ps_session_progress_step(rt->session);
            if (rt->stop)
                break;
            if (ps_session_inline_pending(rt->session))
                continue;
        }
        if (rt->stop)
            break;
        if (read_again)
            lane_fill(lane, &read_again);
        struct ps_watch watches[PS_MAX_SUBFLOWS + 2];
        int nw = ps_session_watches(rt->session, watches, PS_MAX_SUBFLOWS + 2);
        struct pollfd pfds[PS_MAX_SUBFLOWS + 3];
        int np = 0;
        pfds[np].fd = lane->wake_r;
        pfds[np].events = POLLIN;
        pfds[np].revents = 0;
        np++;
        for (int i = 0; i < nw; i++) {
            if (!lane_owns(lane, watches[i].fd))
                continue;
            short ev = 0;
            if (watches[i].want_read)
                ev = (short)(ev | POLLIN);
            if (watches[i].want_write)
                ev = (short)(ev | POLLOUT);
            if (ev == 0)
                continue;
            pfds[np].fd = watches[i].fd;
            pfds[np].events = ev;
            pfds[np].revents = 0;
            watches[np - 1] = watches[i];
            np++;
        }
        int timeout = lane->index == 0 ? ps_session_next_timeout_ms(rt->session) : 1000;
        int pr = poll(pfds, (nfds_t)np, timeout);
        if (rt->stop)
            break;
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            ps_session_fail(rt->session, PS_ERR_IO);
            break;
        }
        if (pfds[0].revents & POLLIN)
            drain_wake(lane->wake_r);
        for (int i = 1; i < np; i++) {
            short ev = pfds[i].revents;
            int fd = watches[i - 1].fd;
            int control = ps_session_is_control(rt->session, fd);
            if (ev & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
                if (control)
                    ps_on_readable(rt->session, fd);
                else {
                    int again = 0;
                    ps_session_ingest(rt->session, fd, &again);
                    if (again)
                        read_again = 1;
                }
            }
            if (ev & POLLOUT) {
                if (control || ps_session_is_connecting(rt->session, fd))
                    ps_on_writable(rt->session, fd);
                else
                    ps_session_flush(rt->session, fd, 4u * 1024u * 1024u);
            }
        }
        if (lane->index == 0)
            ps_session_scale_tick(rt->session);
    }
    return NULL;
}

static int open_lane_pipe(struct io_lane *lane)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(fds[i], F_GETFL, 0);
        if (flags >= 0)
            fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(fds[i], F_GETFD, 0);
        if (flags >= 0)
            fcntl(fds[i], F_SETFD, flags | FD_CLOEXEC);
    }
    lane->wake_r = fds[0];
    lane->wake_w = fds[1];
    return 0;
}

static void close_lane_pipe(struct io_lane *lane)
{
    if (lane->wake_r >= 0)
        close(lane->wake_r);
    if (lane->wake_w >= 0)
        close(lane->wake_w);
    lane->wake_r = lane->wake_w = -1;
}

static int start_runtime(struct ps_runtime *rt)
{
    unsigned n = ps_session_io_lanes(rt->session);
    rt->lanes = (struct io_lane *)calloc(n, sizeof(*rt->lanes));
    if (!rt->lanes)
        return -1;
    rt->nlanes = (int)n;
    for (unsigned i = 0; i < n; i++) {
        rt->lanes[i].rt = rt;
        rt->lanes[i].index = (int)i;
        rt->lanes[i].wake_r = rt->lanes[i].wake_w = -1;
        if (open_lane_pipe(&rt->lanes[i]) != 0) {
            for (unsigned j = 0; j < i; j++)
                close_lane_pipe(&rt->lanes[j]);
            free(rt->lanes);
            rt->lanes = NULL;
            rt->nlanes = 0;
            return -1;
        }
    }
    for (unsigned i = 0; i < n; i++) {
        if (pthread_create(&rt->lanes[i].thread, NULL, runtime_main, &rt->lanes[i]) != 0) {
            rt->stop = 1;
            rt->nlanes = (int)i;
            rt_poke(rt);
            for (unsigned j = 0; j < i; j++)
                pthread_join(rt->lanes[j].thread, NULL);
            for (unsigned j = 0; j < n; j++)
                close_lane_pipe(&rt->lanes[j]);
            free(rt->lanes);
            rt->lanes = NULL;
            rt->nlanes = 0;
            rt->stop = 0;
            return -1;
        }
    }
    rt->started = 1;
    return 0;
}

static void stop_runtime(struct ps_runtime *rt)
{
    if (!rt)
        return;
    rt->stop = 1;
    rt_poke(rt);
    if (rt->started) {
        for (int i = 0; i < rt->nlanes; i++)
            pthread_join(rt->lanes[i].thread, NULL);
        rt->started = 0;
    }
    if (rt->lanes) {
        for (int i = 0; i < rt->nlanes; i++)
            close_lane_pipe(&rt->lanes[i]);
        free(rt->lanes);
        rt->lanes = NULL;
    }
    rt->nlanes = 0;
}

static uint32_t timeout_or(uint32_t value, uint32_t fallback)
{
    return value ? value : fallback;
}

static int bind_cbs(struct ps_runtime *rt, ps_session_t *session)
{
    rt->session = session;
    ps_io_cbs io;
    memset(&io, 0, sizeof(io));
    io.ctx = rt;
    io.poke = rt_poke;
    io.want_io = rt_want;
    /* Callbacks were copied at create time. Replace them. */
    (void)io;
    struct ps_session_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.ctx = rt;
    hooks.register_session = on_register;
    hooks.unregister_session = on_unregister;
    ps_session_set_hooks(session, &hooks);
    return 0;
}

/* The I/O callbacks have to be installed before create returns to user code,
 * but register can run later. poke must be live before the runtime starts,
 * which is after create. Session copies the cbs struct, so we pass them
 * into create. */

static ps_connection_t *connection_new(ps_session_t *session, struct ps_runtime *rt,
                                       uint32_t io_timeout, uint32_t connect_timeout)
{
    ps_connection_t *c = (ps_connection_t *)calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->session = session;
    c->rt = rt;
    c->io_timeout_ms = io_timeout;
    c->connect_timeout_ms = connect_timeout;
    return c;
}

static int tcp_connect_block(const char *host, uint16_t port, int *fd_out,
                             struct sockaddr_storage *peer, socklen_t *peer_len)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    int ga = getaddrinfo(host, portstr, &hints, &res);
    if (ga != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        ps_prepare_socket(fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            memset(peer, 0, sizeof(*peer));
            memcpy(peer, ai->ai_addr, ai->ai_addrlen);
            *peer_len = ai->ai_addrlen;
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return -1;
    *fd_out = fd;
    return 0;
}

static void *data_main(void *arg)
{
    struct ps_listener *ln = (struct ps_listener *)arg;
    while (!ln->stop) {
        struct pollfd pfd;
        pfd.fd = ln->dfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 200);
        if (ln->stop)
            break;
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0 || !(pfd.revents & POLLIN))
            continue;
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int fd = accept(ln->dfd, (struct sockaddr *)&ss, &sl);
        if (fd < 0) {
            if (ln->stop || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            if (errno == EINVAL || errno == EBADF)
                break;
            break;
        }
        uint8_t sid[32];
        uint32_t subflow = 0;
        if (ps_preface_read(fd, sid, &subflow, 5000) != 0) {
            close(fd);
            continue;
        }
        ps_session_t *session = listener_find(ln, sid);
        if (!session) {
            close(fd);
            continue;
        }
        ps_prepare_socket(fd);
        ps_set_nonblock(fd);
        if (ps_embed_adopt_subflow(session, subflow, fd) != 0)
            close(fd);
        ps_session_unref(session);
    }
    return NULL;
}

ps_listener_t *ps_listen(const char *host, uint16_t port, const struct ps_options *options)
{
    ps_ignore_sigpipe();
    ps_log_init();
    const struct ps_tls_config *cfg = options ? options->tls : NULL;
    if (!cfg || !cfg->cert_file || !cfg->key_file)
        return NULL;
    struct ps_listener *ln = (struct ps_listener *)calloc(1, sizeof(*ln));
    if (!ln)
        return NULL;
    ln->cfd = -1;
    ln->dfd = -1;
    pthread_mutex_init(&ln->mu, NULL);
    if (ps_tcp_listen(host, port, &ln->cfd, &ln->cport) != 0 ||
        ps_tcp_listen(host, 0, &ln->dfd, &ln->dport) != 0 ||
        ps_set_nonblock(ln->dfd) != 0) {
        ps_listener_close(ln);
        return NULL;
    }
    ln->cert = strdup(cfg->cert_file);
    ln->key = strdup(cfg->key_file);
    if (cfg->ca_file)
        ln->ca = strdup(cfg->ca_file);
    if (cfg->server_name)
        ln->sni = strdup(cfg->server_name);
    if (!ln->cert || !ln->key) {
        ps_listener_close(ln);
        return NULL;
    }
    ln->tls.cert_file = ln->cert;
    ln->tls.key_file = ln->key;
    ln->tls.ca_file = ln->ca;
    ln->tls.server_name = ln->sni;
    ln->tls.verify_peer = cfg->verify_peer;
    ln->tls.allow_insecure = cfg->allow_insecure;
    if (options)
        ln->opt = *options;
    else
        ps_options_init(&ln->opt);
    ln->opt.tls = &ln->tls;
    ln->ctx = ps_tls_server_ctx(&ln->tls);
    if (!ln->ctx) {
        ps_listener_close(ln);
        return NULL;
    }
    if (pthread_create(&ln->data_thread, NULL, data_main, ln) != 0) {
        ps_listener_close(ln);
        return NULL;
    }
    ln->data_started = 1;
    return ln;
}

void ps_listener_close(ps_listener_t *listener)
{
    if (!listener)
        return;
    listener->stop = 1;
    if (listener->cfd >= 0)
        shutdown(listener->cfd, SHUT_RDWR);
    if (listener->dfd >= 0)
        shutdown(listener->dfd, SHUT_RDWR);
    if (listener->data_started) {
        pthread_join(listener->data_thread, NULL);
        listener->data_started = 0;
    }
    if (listener->cfd >= 0)
        close(listener->cfd);
    if (listener->dfd >= 0)
        close(listener->dfd);
    if (listener->ctx)
        SSL_CTX_free(listener->ctx);
    pthread_mutex_lock(&listener->mu);
    struct map_node *n = listener->map;
    listener->map = NULL;
    pthread_mutex_unlock(&listener->mu);
    while (n) {
        struct map_node *next = n->next;
        ps_session_unref(n->session);
        free(n);
        n = next;
    }
    free(listener->cert);
    free(listener->key);
    free(listener->ca);
    free(listener->sni);
    pthread_mutex_destroy(&listener->mu);
    free(listener);
}

int ps_listener_port(const ps_listener_t *listener, uint16_t *control_port, uint16_t *data_port)
{
    if (!listener)
        return -PS_ERR_INVAL;
    if (control_port)
        *control_port = listener->cport;
    if (data_port)
        *data_port = listener->dport;
    return PS_OK;
}

static ps_connection_t *finish_server(struct ps_listener *ln, int fd, SSL *ssl)
{
    struct ps_runtime *rt = (struct ps_runtime *)calloc(1, sizeof(*rt));
    if (!rt) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }
    rt->listener = ln;
    ps_io_cbs io;
    memset(&io, 0, sizeof(io));
    io.ctx = rt;
    io.poke = rt_poke;
    io.want_io = rt_want;
    if (SSL_CTX_up_ref(ln->ctx) != 1) {
        SSL_free(ssl);
        close(fd);
        free(rt);
        return NULL;
    }
    ps_session_t *session = ps_session_create(1, &ln->opt, ln->ctx, &ln->tls, &io);
    if (!session) {
        SSL_free(ssl);
        close(fd);
        free(rt);
        return NULL;
    }
    rt->session = session;
    struct ps_session_hooks hooks;
    memset(&hooks, 0, sizeof(hooks));
    hooks.ctx = rt;
    hooks.register_session = on_register;
    hooks.unregister_session = on_unregister;
    ps_session_set_hooks(session, &hooks);
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0)
        ps_embed_set_peer(session, (struct sockaddr *)&peer, plen);
    ps_embed_set_data_port(session, ln->dport);
    if (ps_set_nonblock(fd) != 0) {
        SSL_free(ssl);
        close(fd);
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    if (ps_session_attach_ssl(session, ssl, fd, 1) != 0) {
        SSL_free(ssl);
        close(fd);
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    if (start_runtime(rt) != 0) {
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    uint32_t wait = timeout_or(ln->opt.connect_timeout_ms, 10000);
    if (ps_session_wait_open(session, wait) != 0) {
        stop_runtime(rt);
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    return connection_new(session, rt, timeout_or(ln->opt.io_timeout_ms, 120000), wait);
}

ps_connection_t *ps_accept(ps_listener_t *listener)
{
    if (!listener)
        return NULL;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int fd = accept(listener->cfd, (struct sockaddr *)&ss, &sl);
    if (fd < 0)
        return NULL;
    ps_prepare_socket(fd);
    SSL *ssl = ps_tls_wrap(listener->ctx, fd, 1, NULL);
    if (!ssl || ps_tls_handshake_block(ssl, 1) != 0) {
        if (ssl)
            SSL_free(ssl);
        close(fd);
        return NULL;
    }
    return finish_server(listener, fd, ssl);
}

ps_connection_t *ps_connect(const char *host, uint16_t port, const struct ps_options *options)
{
    if (!host || port == 0)
        return NULL;
    ps_ignore_sigpipe();
    ps_log_init();
    struct ps_options opt;
    if (options)
        opt = *options;
    else
        ps_options_init(&opt);
    struct ps_tls_config tls;
    memset(&tls, 0, sizeof(tls));
    if (opt.tls)
        tls = *opt.tls;
    if (!tls.server_name)
        tls.server_name = host;
    opt.tls = &tls;
    int fd = -1;
    struct sockaddr_storage peer;
    socklen_t plen = 0;
    if (tcp_connect_block(host, port, &fd, &peer, &plen) != 0)
        return NULL;
    SSL_CTX *ctx = ps_tls_client_ctx(&tls);
    if (!ctx) {
        close(fd);
        return NULL;
    }
    SSL *ssl = ps_tls_wrap(ctx, fd, 0, tls.server_name);
    if (!ssl || ps_tls_handshake_block(ssl, 0) != 0) {
        if (ssl)
            SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return NULL;
    }
    struct ps_runtime *rt = (struct ps_runtime *)calloc(1, sizeof(*rt));
    if (!rt) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return NULL;
    }
    ps_io_cbs io;
    memset(&io, 0, sizeof(io));
    io.ctx = rt;
    io.poke = rt_poke;
    io.want_io = rt_want;
    ps_session_t *session = ps_session_create(0, &opt, ctx, &tls, &io);
    if (!session) {
        SSL_free(ssl);
        close(fd);
        free(rt);
        return NULL;
    }
    rt->session = session;
    bind_cbs(rt, session);
    ps_embed_set_peer(session, (struct sockaddr *)&peer, plen);
    if (ps_set_nonblock(fd) != 0) {
        SSL_free(ssl);
        close(fd);
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    if (ps_session_attach_ssl(session, ssl, fd, 1) != 0) {
        SSL_free(ssl);
        close(fd);
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    ps_session_handshake_finished(session);
    if (start_runtime(rt) != 0) {
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    uint32_t wait = timeout_or(opt.connect_timeout_ms, 10000);
    if (ps_session_wait_open(session, wait) != 0) {
        stop_runtime(rt);
        ps_embed_close(session);
        free(rt);
        return NULL;
    }
    return connection_new(session, rt, timeout_or(opt.io_timeout_ms, 120000), wait);
}

ssize_t ps_send(ps_connection_t *conn, const void *buffer, size_t length)
{
    if (!conn)
        return -PS_ERR_INVAL;
    return ps_session_send_wait(conn->session, buffer, length, SPT_PROTECTION_CONFIDENTIAL,
                                conn->io_timeout_ms);
}

ssize_t ps_send_protected(ps_connection_t *conn, const void *buffer, size_t length,
                          ps_protection_t protection)
{
    if (!conn)
        return -PS_ERR_INVAL;
    return ps_session_send_wait(conn->session, buffer, length, (uint8_t)protection,
                                conn->io_timeout_ms);
}

ssize_t ps_recv(ps_connection_t *conn, void *buffer, size_t length)
{
    if (!conn)
        return -PS_ERR_INVAL;
    return ps_session_recv_wait(conn->session, buffer, length, conn->io_timeout_ms);
}

int ps_shutdown(ps_connection_t *conn, int how)
{
    if (!conn)
        return -PS_ERR_INVAL;
    if (how == SHUT_RDWR || how == SHUT_WR)
        return ps_session_shutdown_write(conn->session);
    return 0;
}

int ps_close(ps_connection_t *conn)
{
    if (!conn)
        return 0;
    ps_session_shutdown_write(conn->session);
    uint32_t wait = conn->io_timeout_ms ? conn->io_timeout_ms : 5000;
    if (wait > 10000)
        wait = 10000;
    ps_session_wait_flush(conn->session, wait);
    stop_runtime(conn->rt);
    ps_embed_close(conn->session);
    free(conn->rt);
    free(conn);
    return 0;
}

int ps_connection_error(const ps_connection_t *conn)
{
    return conn ? ps_session_error(conn->session) : PS_ERR_INVAL;
}

int ps_connection_state(const ps_connection_t *conn)
{
    return conn ? ps_session_state(conn->session) : PS_STATE_CLOSED;
}

int ps_connection_stats(const ps_connection_t *conn, struct ps_stats *out)
{
    return conn ? ps_session_stats(conn->session, out) : -PS_ERR_INVAL;
}

static int socket_int(int fd, int level, int name, int *out)
{
    int value = 0;
    socklen_t len = sizeof(value);
    if (getsockopt(fd, level, name, &value, &len) != 0)
        return -1;
    *out = value;
    return 0;
}

int ps_connection_tcp_settings(const ps_connection_t *conn, struct ps_tcp_setting *out, int max)
{
    if (!conn || !out || max <= 0)
        return -PS_ERR_INVAL;
    int fds[PS_MAX_SUBFLOWS + 1];
    int data[PS_MAX_SUBFLOWS + 1];
    int n = ps_session_snap_fds(conn->session, fds, data, PS_MAX_SUBFLOWS + 1);
    if (n > max)
        n = max;
    for (int i = 0; i < n; i++) {
        int value = 0;
        int flags = fcntl(fds[i], F_GETFL, 0);
        out[i].data = data[i];
        out[i].nodelay = -1;
        out[i].nonblock = flags < 0 ? -1 : ((flags & O_NONBLOCK) ? 1 : 0);
        out[i].sndbuf = -1;
        out[i].rcvbuf = -1;
        out[i].mss = -1;
        if (socket_int(fds[i], IPPROTO_TCP, TCP_NODELAY, &value) == 0)
            out[i].nodelay = value ? 1 : 0;
        if (socket_int(fds[i], SOL_SOCKET, SO_SNDBUF, &value) == 0)
            out[i].sndbuf = value;
        if (socket_int(fds[i], SOL_SOCKET, SO_RCVBUF, &value) == 0)
            out[i].rcvbuf = value;
        if (socket_int(fds[i], IPPROTO_TCP, TCP_MAXSEG, &value) == 0)
            out[i].mss = value;
    }
    return n;
}

int ps_connection_advice(const ps_connection_t *conn, struct ps_scale_advice *out)
{
    return conn ? ps_session_advice(conn->session, out) : -PS_ERR_INVAL;
}

int ps_rekey(ps_connection_t *conn)
{
    if (!conn)
        return -PS_ERR_INVAL;
    return ps_session_rekey_wait(conn->session, conn->io_timeout_ms);
}
