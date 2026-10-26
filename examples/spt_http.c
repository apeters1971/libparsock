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
            "  spt_http server cert key [port]\n"
            "  spt_http client cert key host port bytes\n");
}

static uint8_t body_byte(size_t off)
{
    return (uint8_t)((off * 131u) ^ (off >> 8));
}

static int read_headers(ps_connection_t *conn, char *buf, size_t cap, size_t *used)
{
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = ps_recv(conn, buf + n, 1);
        if (r <= 0)
            return -1;
        n += (size_t)r;
        buf[n] = 0;
        if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0) {
            *used = n;
            return 0;
        }
    }
    return -1;
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
    char hdr[2048];
    size_t hlen = 0;
    if (read_headers(conn, hdr, sizeof(hdr), &hlen) != 0) {
        ps_close(conn);
        ps_listener_close(ln);
        return 1;
    }
    unsigned long long nbytes = 1024ull * 1024ull;
    if (strncmp(hdr, "GET /", 5) == 0)
        nbytes = strtoull(hdr + 5, NULL, 10);
    if (nbytes == 0)
        nbytes = 1024ull * 1024ull;
    char resp[256];
    int rn = snprintf(resp, sizeof(resp),
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Length: %llu\r\n"
                      "Content-Type: application/octet-stream\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      nbytes);
    if (ps_send(conn, resp, (size_t)rn) != rn) {
        ps_close(conn);
        ps_listener_close(ln);
        return 1;
    }
    uint8_t buf[65536];
    unsigned long long left = nbytes;
    while (left) {
        size_t chunk = sizeof(buf);
        if ((unsigned long long)chunk > left)
            chunk = (size_t)left;
        for (size_t i = 0; i < chunk; i++)
            buf[i] = body_byte((size_t)(nbytes - left) + i);
        ssize_t n = ps_send(conn, buf, chunk);
        if (n <= 0) {
            ps_close(conn);
            ps_listener_close(ln);
            return 1;
        }
        left -= (unsigned long long)n;
    }
    ps_shutdown(conn, SHUT_WR);
    ps_close(conn);
    ps_listener_close(ln);
    return 0;
}

static int run_client(struct ps_options *opt, const char *host, uint16_t port, unsigned long long nbytes)
{
    ps_connection_t *conn = ps_connect(host, port, opt);
    if (!conn)
        return 1;
    char req[256];
    int rn = snprintf(req, sizeof(req),
                      "GET /%llu HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                      nbytes, host);
    if (ps_send(conn, req, (size_t)rn) != rn) {
        ps_close(conn);
        return 1;
    }
    char hdr[2048];
    size_t hlen = 0;
    if (read_headers(conn, hdr, sizeof(hdr), &hlen) != 0) {
        ps_close(conn);
        return 1;
    }
    if (strncmp(hdr, "HTTP/1.1 200", 12) != 0) {
        fprintf(stderr, "unexpected response\n");
        ps_close(conn);
        return 1;
    }
    uint64_t t0 = now_ms();
    unsigned long long got = 0;
    uint8_t buf[65536];
    while (got < nbytes) {
        ssize_t n = ps_recv(conn, buf, sizeof(buf));
        if (n <= 0) {
            fprintf(stderr, "short body %llu/%llu\n", got, nbytes);
            ps_close(conn);
            return 1;
        }
        for (ssize_t i = 0; i < n && got + (unsigned long long)i < nbytes; i++) {
            if (buf[i] != body_byte((size_t)got + (size_t)i)) {
                fprintf(stderr, "body mismatch\n");
                ps_close(conn);
                return 1;
            }
        }
        got += (unsigned long long)n;
    }
    uint64_t dt = now_ms() - t0;
    if (dt == 0)
        dt = 1;
    printf("HTTP/1.1 GET %llu bytes in %llu ms (%.1f MB/s)\n",
           nbytes, (unsigned long long)dt, (double)nbytes / (double)dt / 1000.0);
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
    memset(&tls, 0, sizeof(tls));
    tls.cert_file = argv[2];
    tls.key_file = argv[3];
    tls.ca_file = argv[2];
    tls.verify_peer = 1;
    struct ps_options opt;
    ps_options_init(&opt);
    opt.tls = &tls;
    opt.min_sockets = 4;
    opt.max_sockets = 4;
    opt.initial_sockets = 4;
    if (strcmp(argv[1], "server") == 0)
        return run_server(&opt, argc > 4 ? (uint16_t)atoi(argv[4]) : 0);
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
