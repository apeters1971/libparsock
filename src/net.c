#include "net.h"

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>

void ps_ignore_sigpipe(void)
{
    struct sigaction cur;
    memset(&cur, 0, sizeof(cur));
    if (sigaction(SIGPIPE, NULL, &cur) != 0)
        return;
    if (cur.sa_handler != SIG_DFL)
        return;
    struct sigaction ign;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &ign, NULL);
}

int ps_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

int ps_prepare_socket(int fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    int buf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    return 0;
}

int ps_tcp_listen(const char *host, uint16_t port, int *fd_out, uint16_t *bound_port)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *res = NULL;
    const char *node = (host && host[0]) ? host : NULL;
    int ga = getaddrinfo(node, portstr, &hints, &res);
    if (ga != 0) {
        ps_log("getaddrinfo: %s", gai_strerror(ga));
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        ps_prepare_socket(fd);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 128) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return -1;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) {
        close(fd);
        return -1;
    }
    uint16_t bp = 0;
    if (ss.ss_family == AF_INET)
        bp = ntohs(((struct sockaddr_in *)&ss)->sin_port);
    else if (ss.ss_family == AF_INET6)
        bp = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    *fd_out = fd;
    if (bound_port)
        *bound_port = bp;
    return 0;
}

int ps_tcp_connect_nb(const struct sockaddr *addr, socklen_t len, int *fd_out)
{
    if (!addr || !fd_out || len == 0)
        return -1;
    int fd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    ps_prepare_socket(fd);
    if (ps_set_nonblock(fd) != 0) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, addr, len);
    if (rc == 0) {
        *fd_out = fd;
        return 1;
    }
    if (errno == EINPROGRESS) {
        *fd_out = fd;
        return 0;
    }
    close(fd);
    return -1;
}

int ps_addr_set_port(struct sockaddr *addr, socklen_t len, uint16_t port)
{
    if (!addr)
        return -1;
    if (addr->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
        ((struct sockaddr_in *)addr)->sin_port = htons(port);
        return 0;
    }
    if (addr->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
        return 0;
    }
    return -1;
}

int ps_read_full(int fd, void *buf, size_t len, int timeout_ms)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (pr == 0)
            return -1;
        ssize_t n = recv(pfd.fd, p + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}
