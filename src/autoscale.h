#ifndef PARSOCK_AUTOSCALE_H
#define PARSOCK_AUTOSCALE_H

#include <stdint.h>

enum {
    PS_SC_STABLE = 0,
    PS_SC_PROBE_UP = 1,
    PS_SC_PROBE_DOWN = 2
};

struct ps_scale_state {
    int phase;
    unsigned target;
    unsigned recommended;
    uint64_t baseline_bps;
    uint64_t cooldown_until_ms;
    unsigned stable_rounds;
    int congestion;
};

struct ps_scale_sample {
    uint64_t bytes;
    uint64_t interval_ms;
    uint32_t rtt_us;
    uint32_t rtt_baseline_us;
    uint32_t retrans_delta;
    unsigned sockets;
    unsigned min_sockets;
    unsigned max_sockets;
    int demand;
    uint64_t now_ms;
    uint64_t min_transfer_size;
    int advisory;
};

void ps_scale_state_init(struct ps_scale_state *st, unsigned sockets);
unsigned ps_scale_step(struct ps_scale_state *st, const struct ps_scale_sample *sm);

#endif
