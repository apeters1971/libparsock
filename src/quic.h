#ifndef PARSOCK_QUIC_H
#define PARSOCK_QUIC_H

/*
 * Parallel QUIC backend. Each SPT lane is one ngtcp2 connection and, on
 * the client, its own connected UDP socket. The server listens on one
 * UDP socket and demultiplexes connections by QUIC connection ID.
 * A connection carries one bidirectional stream. The stream is a byte
 * pipe: SPT framing stays above it, and QUIC provides encryption.
 *
 * Without libngtcp2 the same entry points report that QUIC is unavailable.
 */

#include "parsock.h"

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

#define PS_QUIC_MAX_LANES 16

struct ps_quic;

struct ps_quic_cfg {
    int is_server;
    const struct ps_tls_config *tls;
    unsigned max_lanes;
    /* Server: local address of the accepted control socket. Port is ignored. */
    const struct sockaddr *bind_addr;
    socklen_t bind_len;
};

int ps_quic_available(void);
struct ps_quic *ps_quic_open(const struct ps_quic_cfg *cfg, uint16_t *listen_port);
void ps_quic_close(struct ps_quic *quic);
int ps_quic_fds(struct ps_quic *quic, int *fds, int max);
int ps_quic_wants_write(const struct ps_quic *quic);
/* 0 when this socket's receive buffer already holds a full window. */
int ps_quic_wants_read(const struct ps_quic *quic, int fd);
/* Read sockets, run timers, and transmit. 0 on success, -1 if an
   established lane has failed. A handshake that never becomes a lane
   is discarded here. */
int ps_quic_progress(struct ps_quic *quic);
int ps_quic_connect(struct ps_quic *quic, uint32_t lane, const struct sockaddr *peer,
                    socklen_t peer_len);
/* 1 when the handshake is finished and the bidi stream exists. */
int ps_quic_stream_ready(const struct ps_quic *quic, uint32_t lane);
/* Copies what fits. *accepted is the byte count. Returns 0, 1 if the
   stream cannot take data yet, or -1. */
int ps_quic_send(struct ps_quic *quic, uint32_t lane, const void *data, size_t len,
                 size_t *accepted);
/* Copies available stream bytes. *n is 0 when none are buffered. */
int ps_quic_recv(struct ps_quic *quic, uint32_t lane, void *dst, size_t cap, size_t *n);
int ps_quic_unbound(struct ps_quic *quic, unsigned *ids, int max);
size_t ps_quic_unbound_len(const struct ps_quic *quic, unsigned id);
int ps_quic_unbound_copy(const struct ps_quic *quic, unsigned id, size_t off, void *dst,
                         size_t n);
int ps_quic_bind(struct ps_quic *quic, unsigned id, uint32_t lane);
void ps_quic_drop(struct ps_quic *quic, unsigned id);
int ps_quic_exporter(struct ps_quic *quic, uint32_t lane, const uint8_t *context,
                     size_t context_len, uint8_t out[32]);
int ps_quic_exporter_unbound(struct ps_quic *quic, unsigned id, const uint8_t *context,
                             size_t context_len, uint8_t out[32]);
int ps_quic_next_timeout_ms(const struct ps_quic *quic);

#endif
