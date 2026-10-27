#define _GNU_SOURCE

#include "parsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

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
            "  spt_http server cert key [port] [public]\n"
            "  spt_http client cert key host port bytes [public]\n"
            "A missing server certificate and key are written as a self-signed pair.\n");
}

static void openssl_fail(const char *what)
{
    fprintf(stderr, "spt_http: %s\n", what);
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "spt_http: %s\n", buf);
    }
}

static int san_has(const char *list, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = list;
    while (*p) {
        if (strncmp(p, name, nlen) == 0 && (p[nlen] == ',' || p[nlen] == '\0') &&
            (p == list || p[-1] == ','))
            return 1;
        p = strchr(p, ',');
        if (!p)
            break;
        p++;
    }
    return 0;
}

static int san_add(char *list, size_t cap, const char *name)
{
    if (!name || !name[0] || san_has(list, name))
        return 0;
    size_t cur = strlen(list);
    size_t nlen = strlen(name);
    size_t extra = nlen + (cur ? 1 : 0);
    if (cur + extra + 1 > cap)
        return -1;
    if (cur)
        list[cur++] = ',';
    memcpy(list + cur, name, nlen + 1);
    return 0;
}

static int add_dns_name(char *list, size_t cap, const char *host)
{
    if (!host || !host[0] || strcmp(host, "localhost") == 0)
        return 0;
    char dns[300];
    snprintf(dns, sizeof(dns), "DNS:%s", host);
    if (san_add(list, cap, dns) != 0)
        return -1;
    const char *dot = strchr(host, '.');
    if (!dot || dot == host || !dot[1])
        return 0;
    char short_name[256];
    size_t n = (size_t)(dot - host);
    if (n >= sizeof(short_name))
        return -1;
    memcpy(short_name, host, n);
    short_name[n] = '\0';
    snprintf(dns, sizeof(dns), "DNS:%s", short_name);
    return san_add(list, cap, dns);
}

static int certificate_names(char *list, size_t cap)
{
    list[0] = '\0';
    if (san_add(list, cap, "DNS:localhost") != 0 || san_add(list, cap, "IP:127.0.0.1") != 0 ||
        san_add(list, cap, "IP:::1") != 0)
        return -1;
    char host[256];
    host[0] = '\0';
    if (gethostname(host, sizeof(host)) == 0) {
        host[sizeof(host) - 1] = '\0';
        if (add_dns_name(list, cap, host) != 0)
            return -1;
    }
    if (host[0]) {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_CANONNAME;
        if (getaddrinfo(host, NULL, &hints, &res) == 0) {
            int arc = res->ai_canonname ? add_dns_name(list, cap, res->ai_canonname) : 0;
            freeaddrinfo(res);
            if (arc != 0)
                return -1;
        }
    }
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs) != 0)
        return 0;
    for (struct ifaddrs *ifa = ifs; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        char text[INET6_ADDRSTRLEN];
        char name[INET6_ADDRSTRLEN + 4];
        if (ifa->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *addr = (const struct sockaddr_in *)ifa->ifa_addr;
            if (!inet_ntop(AF_INET, &addr->sin_addr, text, sizeof(text)))
                continue;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)ifa->ifa_addr;
            if (!inet_ntop(AF_INET6, &addr->sin6_addr, text, sizeof(text)))
                continue;
        } else {
            continue;
        }
        snprintf(name, sizeof(name), "IP:%s", text);
        if (san_add(list, cap, name) != 0) {
            freeifaddrs(ifs);
            return -1;
        }
    }
    freeifaddrs(ifs);
    return 0;
}

static int write_self_signed(const char *cert_path, const char *key_path)
{
    char names[4096];
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    BIO *cert_bio = NULL;
    BIO *key_bio = NULL;
    X509_EXTENSION *san = NULL;
    X509_EXTENSION *basic = NULL;
    int rc = -1;

    if (certificate_names(names, sizeof(names)) != 0) {
        fprintf(stderr, "spt_http: certificate name list is too long\n");
        return -1;
    }
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) != 1 ||
        EVP_PKEY_keygen(kctx, &key) != 1) {
        openssl_fail("certificate key");
        goto done;
    }
    cert = X509_new();
    if (!cert || X509_set_version(cert, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24 * 365) || X509_set_pubkey(cert, key) != 1) {
        openssl_fail("certificate");
        goto done;
    }
    X509_NAME *name = X509_get_subject_name(cert);
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1,
                                   0) != 1 ||
        X509_set_issuer_name(cert, name) != 1) {
        openssl_fail("certificate name");
        goto done;
    }
    X509V3_CTX ext;
    X509V3_set_ctx_nodb(&ext);
    X509V3_set_ctx(&ext, cert, cert, NULL, NULL, 0);
    san = X509V3_EXT_conf_nid(NULL, &ext, NID_subject_alt_name, names);
    basic = X509V3_EXT_conf_nid(NULL, &ext, NID_basic_constraints, "critical,CA:TRUE");
    if (!san || !basic || X509_add_ext(cert, basic, -1) != 1 || X509_add_ext(cert, san, -1) != 1 ||
        X509_sign(cert, key, EVP_sha256()) == 0) {
        openssl_fail("certificate extensions");
        goto done;
    }
    cert_bio = BIO_new_file(cert_path, "w");
    key_bio = BIO_new_file(key_path, "w");
    if (!cert_bio || !key_bio || PEM_write_bio_X509(cert_bio, cert) != 1 ||
        PEM_write_bio_PrivateKey(key_bio, key, NULL, NULL, 0, NULL, NULL) != 1) {
        openssl_fail("writing certificate");
        unlink(cert_path);
        unlink(key_path);
        goto done;
    }
    BIO_free(cert_bio);
    BIO_free(key_bio);
    cert_bio = NULL;
    key_bio = NULL;
    chmod(key_path, S_IRUSR | S_IWUSR);
    fprintf(stderr, "generated self-signed certificate\n  cert %s\n  key  %s\n", cert_path, key_path);
    rc = 0;
done:
    X509_EXTENSION_free(san);
    X509_EXTENSION_free(basic);
    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kctx);
    return rc;
}

static int ensure_server_cert(const char *cert_path, const char *key_path)
{
    int have_cert = access(cert_path, R_OK) == 0;
    int have_key = access(key_path, R_OK) == 0;
    if (have_cert && have_key)
        return 0;
    if (have_cert != have_key) {
        fprintf(stderr, "spt_http: %s is missing\n", have_cert ? key_path : cert_path);
        return -1;
    }
    return write_self_signed(cert_path, key_path);
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
    if (!ln) {
        fprintf(stderr, "spt_http: listen failed\n");
        return 1;
    }
    uint16_t bound = 0;
    ps_listener_port(ln, &bound, NULL);
    printf("listening %u\n", (unsigned)bound);
    fflush(stdout);
    for (;;) {
        ps_connection_t *conn = ps_accept(ln);
        if (!conn) {
            ps_listener_close(ln);
            return 1;
        }
        char hdr[2048];
        size_t hlen = 0;
        if (read_headers(conn, hdr, sizeof(hdr), &hlen) != 0) {
            fprintf(stderr, "spt_http: request failed: %s\n", ps_strerror(ps_connection_error(conn)));
            ps_close(conn);
            continue;
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
            fprintf(stderr, "spt_http: send failed: %s\n", ps_strerror(ps_connection_error(conn)));
            ps_close(conn);
            continue;
        }
        uint8_t buf[65536];
        unsigned long long left = nbytes;
        int failed = 0;
        while (left) {
            size_t chunk = sizeof(buf);
            if ((unsigned long long)chunk > left)
                chunk = (size_t)left;
            for (size_t i = 0; i < chunk; i++)
                buf[i] = body_byte((size_t)(nbytes - left) + i);
            ssize_t n = opt->min_protection == PS_PROTECTION_AUTHENTICATED
                            ? ps_send_protected(conn, buf, chunk, PS_PROTECTION_AUTHENTICATED)
                            : ps_send(conn, buf, chunk);
            if (n <= 0) {
                fprintf(stderr, "spt_http: send failed: %s\n", ps_strerror(ps_connection_error(conn)));
                failed = 1;
                break;
            }
            left -= (unsigned long long)n;
        }
        if (!failed)
            ps_shutdown(conn, SHUT_WR);
        ps_close(conn);
    }
}

static int run_client(struct ps_options *opt, const char *host, uint16_t port, unsigned long long nbytes)
{
    ps_connection_t *conn = ps_connect(host, port, opt);
    if (!conn) {
        fprintf(stderr, "spt_http: connect failed\n");
        return 1;
    }
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
            fprintf(stderr, "short body %llu/%llu: %s\n", got, nbytes,
                    ps_strerror(ps_connection_error(conn)));
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
    if (strcmp(argv[1], "server") == 0) {
        int public_body = (argc > 4 && strcmp(argv[4], "public") == 0) ||
                          (argc > 5 && strcmp(argv[5], "public") == 0);
        uint16_t port = 0;
        if (argc > 4 && strcmp(argv[4], "public") != 0)
            port = (uint16_t)atoi(argv[4]);
        if (public_body)
            opt.min_protection = PS_PROTECTION_AUTHENTICATED;
        if (ensure_server_cert(argv[2], argv[3]) != 0)
            return 1;
        return run_server(&opt, port);
    }
    if (strcmp(argv[1], "client") == 0) {
        if (argc < 7) {
            usage();
            return 2;
        }
        if (argc > 7 && strcmp(argv[7], "public") == 0)
            opt.min_protection = PS_PROTECTION_AUTHENTICATED;
        if (access(argv[2], R_OK) != 0 || access(argv[3], R_OK) != 0) {
            fprintf(stderr, "spt_http: certificate %s or key %s is missing\n", argv[2], argv[3]);
            return 1;
        }
        tls.server_name = argv[4];
        return run_client(&opt, argv[4], (uint16_t)atoi(argv[5]), strtoull(argv[6], NULL, 10));
    }
    usage();
    return 2;
}
