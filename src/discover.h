#ifndef PARSOCK_DISCOVER_H
#define PARSOCK_DISCOVER_H

#include <stdint.h>

struct ps_hwinfo {
    uint64_t link_bps;
    unsigned rx_queues;
    unsigned tx_queues;
    unsigned cpus;
    int numa_node;
    uint32_t rtt_us;
    char ifname[16];
};

void ps_discover_fd(int fd, struct ps_hwinfo *out);
int ps_tcp_stats(int fd, uint32_t *rtt_us, uint64_t *retrans);
unsigned ps_suggest_sockets(const struct ps_hwinfo *hw, unsigned min_sockets,
                            unsigned max_sockets);
uint64_t ps_bdp_bytes(uint64_t link_bps, uint32_t rtt_us);

#endif
