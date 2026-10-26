#include "parsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void usage(void)
{
    fprintf(stderr,
            "usage:\n"
            "  spt_bulk server cert key [port]\n"
            "  spt_bulk client cert key host port bytes\n");
}

static int fill_opt(struct ps_options *opt, struct ps_tls_config *tls, const char *cert,
                    const char *key, int insecure)
{
    memset(tls, 0, sizeof(*tls));
    tls->cert_file = cert;
    tls->key_file = key;
    tls->ca_file = cert;
    tls->allow_insecure = insecure;
    tls->verify_peer = insecure ? 0 : 1;
    ps_options_init(opt);
    opt->tls = tls;
    opt->min_sockets = 4;
    opt->max_sockets = 4;
    opt->initial_sockets = 4;
    opt->worker_threads = 2;
    return 0;
}

static int run_server(struct ps_options *opt, uint16_t port)
{
    ps_listener_t *ln = ps_listen(port ? "0.0.0.0" : "127.0.0.1", port, opt);
    if (!ln)
        return 1;
    uint16_t bound = 0;
    ps_listener_port(ln, &bound, NULL);
    printf("listening %u\n", (unsigned)bound);
    fflush(stdout);
    ps_connection_t *conn = ps_accept(ln);
    if (!conn) {
        ps_listener_close(ln);
        return 1;
    }
    uint8_t buf[65536];
    uint64_t total = 0;
    uint64_t t0 = now_ms();
    for (;;) {
        ssize_t n = ps_recv(conn, buf, sizeof(buf));
        if (n < 0) {
            fprintf(stderr, "recv: %s\n", ps_strerror(ps_connection_error(conn)));
            ps_close(conn);
            ps_listener_close(ln);
            return 1;
        }
        if (n == 0)
            break;
        total += (uint64_t)n;
    }
    uint64_t dt = now_ms() - t0;
    if (dt == 0)
        dt = 1;
    printf("received %llu bytes in %llu ms (%.1f MB/s)\n",
           (unsigned long long)total, (unsigned long long)dt,
           (double)total / (double)dt / 1000.0);
    ps_close(conn);
    ps_listener_close(ln);
    return 0;
}

static int run_client(struct ps_options *opt, const char *host, uint16_t port, uint64_t nbytes)
{
    ps_connection_t *conn = ps_connect(host, port, opt);
    if (!conn) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }
    uint8_t buf[65536];
    memset(buf, 0x5a, sizeof(buf));
    uint64_t left = nbytes;
    uint64_t t0 = now_ms();
    while (left) {
        size_t chunk = sizeof(buf);
        if ((uint64_t)chunk > left)
            chunk = (size_t)left;
        ssize_t n = ps_send(conn, buf, chunk);
        if (n <= 0) {
            fprintf(stderr, "send: %s\n", ps_strerror(ps_connection_error(conn)));
            ps_close(conn);
            return 1;
        }
        left -= (uint64_t)n;
    }
    ps_shutdown(conn, SHUT_WR);
    uint64_t dt = now_ms() - t0;
    if (dt == 0)
        dt = 1;
    printf("sent %llu bytes in %llu ms (%.1f MB/s)\n",
           (unsigned long long)nbytes, (unsigned long long)dt,
           (double)nbytes / (double)dt / 1000.0);
    ps_close(conn);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        usage();
        return 2;
    }
    struct ps_tls_config tls;
    struct ps_options opt;
    fill_opt(&opt, &tls, argv[2], argv[3], 0);
    if (strcmp(argv[1], "server") == 0) {
        uint16_t port = argc > 4 ? (uint16_t)atoi(argv[4]) : 0;
        return run_server(&opt, port);
    }
    if (strcmp(argv[1], "client") == 0) {
        if (argc < 7) {
            usage();
            return 2;
        }
        tls.server_name = argv[4];
        return run_client(&opt, argv[4], (uint16_t)atoi(argv[5]), strtoull(argv[6], NULL, 10));
    }
    usage();
    return 2;
}
