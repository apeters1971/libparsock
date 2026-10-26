#ifndef PARSOCK_NET_H
#define PARSOCK_NET_H

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

void ps_ignore_sigpipe(void);
int ps_set_nonblock(int fd);
int ps_prepare_socket(int fd);
int ps_tcp_listen(const char *host, uint16_t port, int *fd_out, uint16_t *bound_port);
int ps_tcp_connect_nb(const struct sockaddr *addr, socklen_t len, int *fd_out);
int ps_addr_set_port(struct sockaddr *addr, socklen_t len, uint16_t port);
int ps_read_full(int fd, void *buf, size_t len, int timeout_ms);

#endif
