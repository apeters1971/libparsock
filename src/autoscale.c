#include "autoscale.h"

#include <string.h>

void ps_scale_state_init(struct ps_scale_state *st, unsigned sockets)
{
    memset(st, 0, sizeof(*st));
    if (sockets == 0)
        sockets = 1;
    st->target = sockets;
    st->recommended = sockets;
    st->phase = PS_SC_STABLE;
}

static unsigned clamp_sockets(unsigned n, unsigned min_s, unsigned max_s)
{
    if (max_s < min_s)
        max_s = min_s;
    if (n < min_s)
        n = min_s;
    if (n > max_s)
        n = max_s;
    if (n == 0)
        n = 1;
    return n;
}

static unsigned half_up(unsigned n, unsigned min_s, unsigned max_s)
{
    unsigned next = n * 2;
    if (next < n)
        next = max_s;
    return clamp_sockets(next, min_s, max_s);
}

static unsigned half_down(unsigned n, unsigned min_s, unsigned max_s)
{
    unsigned next = n > 1 ? n / 2 : 1;
    return clamp_sockets(next, min_s, max_s);
}

unsigned ps_scale_step(struct ps_scale_state *st, const struct ps_scale_sample *sm)
{
    if (!st || !sm)
        return 1;
    unsigned cur = sm->sockets ? sm->sockets : 1;
    unsigned min_s = sm->min_sockets ? sm->min_sockets : 1;
    unsigned max_s = sm->max_sockets ? sm->max_sockets : cur;
    cur = clamp_sockets(cur, 1, max_s > 0 ? max_s : cur);

    uint64_t bps = 0;
    if (sm->interval_ms > 0)
        bps = sm->bytes * 1000ull / sm->interval_ms;

    int congestion = 0;
    if (sm->rtt_baseline_us >= 5000 &&
        sm->rtt_us > sm->rtt_baseline_us + sm->rtt_baseline_us / 2)
        congestion = 1;
    if (sm->retrans_delta > 10)
        congestion = 1;
    st->congestion = congestion;

    if (sm->advisory) {
        unsigned rec = cur;
        if (sm->now_ms < st->cooldown_until_ms) {
            st->recommended = st->target ? st->target : rec;
            return cur;
        }
        if (congestion)
            rec = half_down(cur, min_s, max_s);
        else if (sm->demand && sm->bytes >= sm->min_transfer_size)
            rec = half_up(cur, min_s, max_s);
        st->recommended = rec;
        st->target = rec;
        st->cooldown_until_ms = sm->now_ms + (sm->interval_ms ? sm->interval_ms : 1);
        return cur;
    }

    if (congestion && cur > min_s) {
        unsigned next = half_down(cur, min_s, max_s);
        st->phase = PS_SC_STABLE;
        st->target = next;
        st->recommended = next;
        st->baseline_bps = bps;
        st->stable_rounds = 0;
        st->cooldown_until_ms = sm->now_ms + sm->interval_ms * 2;
        return next;
    }

    if (sm->now_ms < st->cooldown_until_ms)
        return st->target ? st->target : cur;

    int measured = sm->demand && sm->bytes >= sm->min_transfer_size && sm->interval_ms > 0;

    if (st->phase == PS_SC_PROBE_UP) {
        if (!measured)
            return st->target ? st->target : cur;
        int improved = st->baseline_bps == 0 || bps * 10 >= st->baseline_bps * 11;
        st->phase = PS_SC_STABLE;
        st->stable_rounds = 0;
        st->cooldown_until_ms = sm->now_ms + sm->interval_ms * 2;
        if (improved) {
            st->target = cur;
            st->recommended = cur;
            st->baseline_bps = bps;
            return cur;
        }
        unsigned next = half_down(cur, min_s, max_s);
        st->target = next;
        st->recommended = next;
        st->baseline_bps = bps;
        return next;
    }

    if (st->phase == PS_SC_PROBE_DOWN) {
        if (!measured)
            return st->target ? st->target : cur;
        int regressed = st->baseline_bps > 0 && bps * 10 < st->baseline_bps * 9;
        st->phase = PS_SC_STABLE;
        st->stable_rounds = 0;
        st->cooldown_until_ms = sm->now_ms + sm->interval_ms * 2;
        if (regressed) {
            unsigned next = half_up(cur, min_s, max_s);
            st->target = next;
            st->recommended = next;
            return next;
        }
        st->target = cur;
        st->recommended = cur;
        st->baseline_bps = bps;
        return cur;
    }

    if (!measured) {
        st->recommended = st->target ? st->target : cur;
        return st->target ? st->target : cur;
    }

    st->stable_rounds++;
    st->baseline_bps = bps;
    st->target = cur;
    st->recommended = cur;
    if (st->stable_rounds >= 2 && cur < max_s) {
        unsigned next = half_up(cur, min_s, max_s);
        if (next != cur) {
            st->phase = PS_SC_PROBE_UP;
            st->target = next;
            st->recommended = next;
            return next;
        }
    }
    if (st->stable_rounds >= 6 && cur > min_s) {
        unsigned next = half_down(cur, min_s, max_s);
        if (next != cur) {
            st->phase = PS_SC_PROBE_DOWN;
            st->target = next;
            st->recommended = next;
            return next;
        }
    }
    return cur;
}
