#include "autoscale.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        fails++;
    }
}

static struct ps_scale_sample base(void)
{
    struct ps_scale_sample sm;
    memset(&sm, 0, sizeof(sm));
    sm.bytes = 2ull << 20;
    sm.interval_ms = 500;
    sm.sockets = 2;
    sm.min_sockets = 1;
    sm.max_sockets = 16;
    sm.demand = 1;
    sm.now_ms = 1000;
    sm.min_transfer_size = 1ull << 20;
    return sm;
}

int main(void)
{
    struct ps_scale_state st;
    ps_scale_state_init(&st, 2);
    struct ps_scale_sample sm = base();
    expect(ps_scale_step(&st, &sm) == 2, "first stable");
    sm.now_ms = 2000;
    expect(ps_scale_step(&st, &sm) == 4, "probe up");
    expect(st.phase == PS_SC_PROBE_UP, "phase up");
    sm.sockets = 4;
    sm.now_ms = 3000;
    sm.bytes = 8ull << 20;
    expect(ps_scale_step(&st, &sm) == 4, "keep improvement");
    expect(st.phase == PS_SC_STABLE, "back to stable");

    ps_scale_state_init(&st, 4);
    sm = base();
    sm.sockets = 4;
    sm.max_sockets = 16;
    expect(ps_scale_step(&st, &sm) == 4, "stable 1");
    sm.now_ms = 2000;
    unsigned up = ps_scale_step(&st, &sm);
    expect(up == 8, "probe 8");
    sm.sockets = 8;
    sm.now_ms = 3000;
    sm.bytes = 1ull << 20;
    expect(ps_scale_step(&st, &sm) == 4, "revert weak probe");

    ps_scale_state_init(&st, 4);
    sm = base();
    sm.sockets = 4;
    sm.rtt_baseline_us = 10000;
    sm.rtt_us = 20000;
    expect(ps_scale_step(&st, &sm) == 2, "rtt congestion");

    ps_scale_state_init(&st, 4);
    sm = base();
    sm.sockets = 4;
    sm.rtt_baseline_us = 1000;
    sm.rtt_us = 4000;
    expect(ps_scale_step(&st, &sm) == 4, "coarse rtt ignored");
    sm.retrans_delta = 11;
    sm.now_ms = 5000;
    expect(ps_scale_step(&st, &sm) == 2, "retrans");

    ps_scale_state_init(&st, 2);
    sm = base();
    sm.advisory = 1;
    expect(ps_scale_step(&st, &sm) == 2, "advisory count");
    expect(st.recommended == 4, "advisory rec");

    if (fails) {
        fprintf(stderr, "%d autoscale checks failed\n", fails);
        return 1;
    }
    return 0;
}
