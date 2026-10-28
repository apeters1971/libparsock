#ifndef PARSOCK_RDMA_H
#define PARSOCK_RDMA_H

/*
 * RDMA RC SEND/RECV backend. The TCP session calls these operations.
 * Without librdmacm the same entry points report that RDMA is unavailable.
 * A receive buffer pointer stays valid until ps_rdma_recycle.
 */

#include "parsock.h"

#include <sys/socket.h>

struct ps_rdma;

struct ps_rdma_cfg {
    int is_server;
    const char *device;
    unsigned send_depth;
    unsigned recv_depth;
    unsigned max_lanes;
    size_t message_bytes;
    /* Server: local address of the accepted control socket. Port is ignored. */
    const struct sockaddr *bind_addr;
    socklen_t bind_len;
};

enum {
    PS_RDMA_EV_CONNECTED = 1,
    PS_RDMA_EV_RECV = 2,
    PS_RDMA_EV_ERROR = 3
};

struct ps_rdma_event {
    int type;
    uint32_t lane;
    const uint8_t *data;
    size_t len;
    unsigned slot;
};

int ps_rdma_available(void);
/* Shrink send and recv so every lane fits in RLIMIT_MEMLOCK. Returns -1 when
   the minimum queue, 2 sends and 4 receives, does not fit. */
int ps_rdma_clamp_depths(size_t message, unsigned lanes, unsigned *send_depth,
                         unsigned *recv_depth, int quiet);
struct ps_rdma *ps_rdma_open(const struct ps_rdma_cfg *cfg, uint16_t *listen_port);
void ps_rdma_close(struct ps_rdma *rdma);
int ps_rdma_fds(struct ps_rdma *rdma, int *fds, int max);
int ps_rdma_authorize(struct ps_rdma *rdma, uint32_t lane, const uint8_t token[32]);
int ps_rdma_connect(struct ps_rdma *rdma, uint32_t lane, const struct sockaddr *peer,
                    socklen_t peer_len, const uint8_t token[32]);
int ps_rdma_progress(struct ps_rdma *rdma, struct ps_rdma_event *ev, int max, unsigned budget);
int ps_rdma_send(struct ps_rdma *rdma, uint32_t lane, const void *data, size_t len);
int ps_rdma_recycle(struct ps_rdma *rdma, uint32_t lane, unsigned slot);
int ps_rdma_register_device_mem(struct ps_rdma *rdma, struct ps_device_mem *mem);
int ps_rdma_deregister_device_mem(struct ps_rdma *rdma, struct ps_device_mem *mem);

#endif
