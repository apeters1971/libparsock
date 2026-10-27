#include "rdma.h"

#include "log.h"
#include "net.h"
#include "spt_wire.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(PARSOCK_HAVE_RDMA)

#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

enum {
    LANE_FREE = 0,
    LANE_AUTH = 1,
    LANE_RESOLVE = 2,
    LANE_UP = 3,
    LANE_DEAD = 4
};

struct rdma_lane {
    int state;
    struct rdma_cm_id *id;
    uint8_t token[32];
    uint8_t *mem;
    struct ibv_mr *mrs[512];
    size_t stride;
    unsigned char send_used[256];
    unsigned char recv_held[256];
    int buffers;
    int qp;
};

struct ps_rdma {
    pthread_mutex_t mu;
    int closing;
    int is_server;
    char *device;
    unsigned send_depth;
    unsigned recv_depth;
    unsigned max_lanes;
    size_t message_bytes;
    struct rdma_event_channel *ec;
    struct rdma_cm_id *listen;
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_comp_channel *comp;
    struct rdma_lane lanes[PS_MAX_SUBFLOWS];
};

static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint64_t pack_wr(unsigned kind, unsigned lane, unsigned slot)
{
    return ((uint64_t)kind << 32) | ((uint64_t)lane << 16) | (uint64_t)slot;
}

static void unpack_wr(uint64_t wr, unsigned *kind, unsigned *lane, unsigned *slot)
{
    *kind = (unsigned)(wr >> 32);
    *lane = (unsigned)((wr >> 16) & 0xffffu);
    *slot = (unsigned)(wr & 0xffffu);
}

static int depth_ok(unsigned send_depth, unsigned recv_depth, unsigned lanes, size_t message)
{
    if (send_depth < 2 || send_depth > 256 || recv_depth < 4 || recv_depth > 256)
        return 0;
    if (lanes < 1 || lanes > PS_MAX_SUBFLOWS)
        return 0;
    if (message < SPT_FRAME_HEADER_LEN + SPT_TAG_LEN || message > SPT_MAX_FRAME)
        return 0;
    return 1;
}

static int ensure_device(struct ps_rdma *r, struct ibv_context *ctx)
{
    if (!ctx)
        return -1;
    const char *name = ibv_get_device_name(ctx->device);
    if (r->device && name && strcmp(name, r->device) != 0) {
        ps_notice("rdma device %s does not match %s", name ? name : "?", r->device);
        return -1;
    }
    if (!r->ctx) {
        int cqe = (int)(r->max_lanes * (r->send_depth + r->recv_depth));
        if (cqe < 16)
            cqe = 16;
        r->ctx = ctx;
        r->pd = ibv_alloc_pd(ctx);
        r->comp = ibv_create_comp_channel(ctx);
        if (!r->pd || !r->comp) {
            ps_notice("rdma protection domain or completion channel failed");
            return -1;
        }
        set_nonblock(r->comp->fd);
        r->cq = ibv_create_cq(ctx, cqe, NULL, r->comp, 0);
        if (!r->cq || ibv_req_notify_cq(r->cq, 0) != 0) {
            ps_notice("rdma completion queue failed");
            return -1;
        }
        ps_notice("rdma device %s cq=%d", name ? name : "?", cqe);
    }
    if (ctx != r->ctx) {
        ps_notice("rdma connection resolved a different device");
        return -1;
    }
    return 0;
}

static size_t host_page(void)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page < 4096)
        page = 4096;
    return (size_t)page;
}

static void format_rlim(rlim_t value, char *out, size_t n)
{
    if (value == RLIM_INFINITY)
        snprintf(out, n, "unlimited");
    else
        snprintf(out, n, "%llu", (unsigned long long)value);
}

/* ibv_reg_mr pins pages and charges them to RLIMIT_MEMLOCK. A 256 KiB frame
   with the default queue depths is about 20 MiB, above the usual 64 KiB soft
   limit. Raise it when the hard limit allows. */
static void raise_memlock(size_t bytes)
{
    struct rlimit lim;
    if (getrlimit(RLIMIT_MEMLOCK, &lim) != 0)
        return;
    if (lim.rlim_cur == RLIM_INFINITY || lim.rlim_cur >= (rlim_t)bytes)
        return;
    struct rlimit up;
    up.rlim_cur = RLIM_INFINITY;
    up.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_MEMLOCK, &up) == 0)
        return;
    if (lim.rlim_max > lim.rlim_cur) {
        up.rlim_cur = lim.rlim_max;
        up.rlim_max = lim.rlim_max;
        setrlimit(RLIMIT_MEMLOCK, &up);
    }
}

static size_t slot_stride(size_t message)
{
    size_t page = host_page();
    return (message + page - 1u) & ~(page - 1u);
}

int ps_rdma_clamp_depths(size_t message, unsigned lanes, unsigned *send_depth, unsigned *recv_depth,
                         int quiet)
{
    if (!send_depth || !recv_depth || lanes < 1 || message == 0)
        return -1;
    unsigned send = *send_depth;
    unsigned recv = *recv_depth;
    if (send < 2)
        send = 2;
    if (recv < 4)
        recv = 4;
    if (send > 256)
        send = 256;
    if (recv > 256)
        recv = 256;
    size_t stride = slot_stride(message);
    raise_memlock(stride * (size_t)(send + recv) * (size_t)lanes);
    struct rlimit lim;
    if (getrlimit(RLIMIT_MEMLOCK, &lim) != 0 || lim.rlim_cur == RLIM_INFINITY) {
        *send_depth = send;
        *recv_depth = recv;
        return 0;
    }
    size_t budget = (size_t)lim.rlim_cur / stride;
    if (budget / lanes < 6)
        return -1;
    unsigned per = (unsigned)(budget / lanes);
    if (per > 512)
        per = 512;
    /* Outstanding data is limited by both queues. Shrink the larger one first. */
    while ((size_t)send + recv > per) {
        if (recv >= send && recv > 4)
            recv--;
        else if (send > 2)
            send--;
        else if (recv > 4)
            recv--;
        else
            return -1;
    }
    if (!quiet && (send != *send_depth || recv != *recv_depth)) {
        char soft[32];
        format_rlim(lim.rlim_cur, soft, sizeof(soft));
        ps_notice("rdma queue depths reduced to send %u recv %u to fit memlock %s", send, recv, soft);
    }
    *send_depth = send;
    *recv_depth = recv;
    return 0;
}

static int setup_buffers(struct ps_rdma *r, struct rdma_lane *ln)
{
    if (ln->buffers)
        return 0;
    /* One MR per slot. irdma returns ENOMEM for a single registration of the
       whole queue (about 20 MiB). Each slot stays under one page-aligned frame. */
    size_t stride = slot_stride(r->message_bytes);
    unsigned nslots = r->send_depth + r->recv_depth;
    if (nslots > 512)
        return -1;
    size_t alloc = stride * (size_t)nslots;
    raise_memlock(alloc);
    void *raw = NULL;
    int arc = posix_memalign(&raw, host_page(), alloc);
    if (arc != 0) {
        ps_notice("rdma buffer allocation failed: %s (%zu bytes)", strerror(arc), alloc);
        return -1;
    }
    uint8_t *mem = (uint8_t *)raw;
    memset(mem, 0, alloc);
    for (unsigned i = 0; i < nslots; i++) {
        ln->mrs[i] = ibv_reg_mr(r->pd, mem + stride * (size_t)i, stride, IBV_ACCESS_LOCAL_WRITE);
        if (!ln->mrs[i]) {
            int saved = errno;
            struct rlimit lim;
            memset(&lim, 0, sizeof(lim));
            getrlimit(RLIMIT_MEMLOCK, &lim);
            char soft[32];
            char hard[32];
            format_rlim(lim.rlim_cur, soft, sizeof(soft));
            format_rlim(lim.rlim_max, hard, sizeof(hard));
            ps_notice("rdma memory registration failed: %s (region %u of %u, %zu bytes, %zu bytes total, memlock soft %s hard %s)",
                      strerror(saved), i, nslots, stride, alloc, soft, hard);
            for (unsigned j = 0; j < i; j++) {
                ibv_dereg_mr(ln->mrs[j]);
                ln->mrs[j] = NULL;
            }
            free(mem);
            return -1;
        }
    }
    ln->mem = mem;
    ln->stride = stride;
    ln->buffers = 1;
    ps_notice("rdma registered %zu bytes in %u regions", alloc, nslots);
    return 0;
}

static int post_recv_slot(struct ps_rdma *r, struct rdma_lane *ln, unsigned slot)
{
    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)(ln->mem + ln->stride * (r->send_depth + slot));
    sge.length = (uint32_t)r->message_bytes;
    sge.lkey = ln->mrs[r->send_depth + slot]->lkey;
    struct ibv_recv_wr wr;
    struct ibv_recv_wr *bad = NULL;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id = pack_wr(2, (unsigned)(ln - r->lanes), slot);
    wr.sg_list = &sge;
    wr.num_sge = 1;
    if (ibv_post_recv(ln->id->qp, &wr, &bad) != 0) {
        ps_notice("rdma post recv failed: %s", strerror(errno));
        return -1;
    }
    ln->recv_held[slot] = 0;
    return 0;
}

static int post_all_recvs(struct ps_rdma *r, struct rdma_lane *ln)
{
    for (unsigned i = 0; i < r->recv_depth; i++) {
        if (post_recv_slot(r, ln, i) != 0)
            return -1;
    }
    return 0;
}

static int create_lane_qp(struct ps_rdma *r, struct rdma_lane *ln)
{
    if (ln->qp)
        return 0;
    struct ibv_qp_init_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_type = IBV_QPT_RC;
    attr.send_cq = r->cq;
    attr.recv_cq = r->cq;
    attr.cap.max_send_wr = r->send_depth;
    attr.cap.max_recv_wr = r->recv_depth;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    if (rdma_create_qp(ln->id, r->pd, &attr) != 0) {
        ps_notice("rdma create qp failed: %s", strerror(errno));
        return -1;
    }
    ln->qp = 1;
    return 0;
}

static void free_lane_buffers(struct rdma_lane *ln)
{
    for (unsigned i = 0; i < 512; i++) {
        if (ln->mrs[i]) {
            ibv_dereg_mr(ln->mrs[i]);
            ln->mrs[i] = NULL;
        }
    }
    free(ln->mem);
    ln->mem = NULL;
    ln->buffers = 0;
}

static int arm_connected(struct ps_rdma *r, struct rdma_lane *ln)
{
    if (ensure_device(r, ln->id->verbs) != 0)
        return -1;
    if (setup_buffers(r, ln) != 0 || create_lane_qp(r, ln) != 0 || post_all_recvs(r, ln) != 0)
        return -1;
    return 0;
}

static struct rdma_conn_param conn_param(const void *token)
{
    struct rdma_conn_param cp;
    memset(&cp, 0, sizeof(cp));
    cp.responder_resources = 4;
    cp.initiator_depth = 4;
    cp.retry_count = 7;
    cp.rnr_retry_count = 7;
    cp.private_data = token;
    cp.private_data_len = token ? 32 : 0;
    return cp;
}

static int emit(struct ps_rdma_event *ev, int *n, int max, int type, uint32_t lane,
                const uint8_t *data, size_t len, unsigned slot)
{
    if (*n >= max)
        return -1;
    ev[*n].type = type;
    ev[*n].lane = lane;
    ev[*n].data = data;
    ev[*n].len = len;
    ev[*n].slot = slot;
    (*n)++;
    return 0;
}

static int handle_cm(struct ps_rdma *r, struct rdma_cm_event *event, struct ps_rdma_event *ev, int *n,
                     int max)
{
    enum rdma_cm_event_type kind = event->event;
    struct rdma_cm_id *id = event->id;
    uint8_t priv[32];
    int priv_len = 0;
    if (event->param.conn.private_data && event->param.conn.private_data_len > 0) {
        priv_len = (int)event->param.conn.private_data_len;
        if (priv_len > 32)
            priv_len = 32;
        memcpy(priv, event->param.conn.private_data, (size_t)priv_len);
    }
    rdma_ack_cm_event(event);

    if (kind == RDMA_CM_EVENT_CONNECT_REQUEST) {
        struct rdma_lane *match = NULL;
        if (priv_len == 32) {
            for (unsigned i = 0; i < PS_MAX_SUBFLOWS; i++) {
                struct rdma_lane *ln = &r->lanes[i];
                if (ln->state == LANE_AUTH && memcmp(ln->token, priv, 32) == 0) {
                    match = ln;
                    break;
                }
            }
        }
        if (!match) {
            ps_notice("rdma connect request rejected");
            rdma_reject(id, NULL, 0);
            return 0;
        }
        match->id = id;
        if (arm_connected(r, match) != 0) {
            if (match->qp && match->id)
                rdma_destroy_qp(match->id);
            match->qp = 0;
            free_lane_buffers(match);
            rdma_reject(id, NULL, 0);
            match->id = NULL;
            match->state = LANE_DEAD;
            return emit(ev, n, max, PS_RDMA_EV_ERROR, (uint32_t)(match - r->lanes), NULL, 0, 0);
        }
        struct rdma_conn_param cp = conn_param(NULL);
        if (rdma_accept(id, &cp) != 0) {
            ps_notice("rdma accept failed: %s", strerror(errno));
            match->state = LANE_DEAD;
            return emit(ev, n, max, PS_RDMA_EV_ERROR, (uint32_t)(match - r->lanes), NULL, 0, 0);
        }
        return 0;
    }

    struct rdma_lane *ln = NULL;
    for (unsigned i = 0; i < PS_MAX_SUBFLOWS; i++) {
        if (r->lanes[i].id == id) {
            ln = &r->lanes[i];
            break;
        }
    }
    if (!ln)
        return 0;
    uint32_t lane = (uint32_t)(ln - r->lanes);

    if (kind == RDMA_CM_EVENT_ADDR_RESOLVED) {
        if (rdma_resolve_route(id, 2000) != 0) {
            ps_notice("rdma resolve route failed: %s", strerror(errno));
            ln->state = LANE_DEAD;
            return emit(ev, n, max, PS_RDMA_EV_ERROR, lane, NULL, 0, 0);
        }
        return 0;
    }
    if (kind == RDMA_CM_EVENT_ROUTE_RESOLVED) {
        if (arm_connected(r, ln) != 0) {
            ln->state = LANE_DEAD;
            return emit(ev, n, max, PS_RDMA_EV_ERROR, lane, NULL, 0, 0);
        }
        struct rdma_conn_param cp = conn_param(ln->token);
        if (rdma_connect(id, &cp) != 0) {
            ps_notice("rdma connect failed: %s", strerror(errno));
            ln->state = LANE_DEAD;
            return emit(ev, n, max, PS_RDMA_EV_ERROR, lane, NULL, 0, 0);
        }
        return 0;
    }
    if (kind == RDMA_CM_EVENT_ESTABLISHED) {
        ln->state = LANE_UP;
        ps_notice("rdma lane %u established", lane);
        return emit(ev, n, max, PS_RDMA_EV_CONNECTED, lane, NULL, 0, 0);
    }
    if (kind == RDMA_CM_EVENT_DISCONNECTED || kind == RDMA_CM_EVENT_DEVICE_REMOVAL ||
        kind == RDMA_CM_EVENT_ADDR_ERROR || kind == RDMA_CM_EVENT_ROUTE_ERROR ||
        kind == RDMA_CM_EVENT_CONNECT_ERROR || kind == RDMA_CM_EVENT_UNREACHABLE ||
        kind == RDMA_CM_EVENT_REJECTED || kind == RDMA_CM_EVENT_ADDR_CHANGE) {
        ps_notice("rdma lane %u %s", lane, rdma_event_str(kind));
        ln->state = LANE_DEAD;
        return emit(ev, n, max, PS_RDMA_EV_ERROR, lane, NULL, 0, 0);
    }
    return 0;
}

static int poll_cm(struct ps_rdma *r, struct ps_rdma_event *ev, int *n, int max)
{
    if (!r->ec)
        return 0;
    for (;;) {
        if (*n >= max)
            return 0;
        struct pollfd pfd;
        pfd.fd = r->ec->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 0);
        if (pr <= 0 || (pfd.revents & POLLIN) == 0)
            return 0;
        struct rdma_cm_event *event = NULL;
        if (rdma_get_cm_event(r->ec, &event) != 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            ps_notice("rdma cm event failed: %s", strerror(errno));
            return -1;
        }
        if (handle_cm(r, event, ev, n, max) != 0)
            return -1;
    }
}

static void drain_notify(struct ps_rdma *r)
{
    if (!r->comp || !r->cq)
        return;
    struct pollfd pfd;
    pfd.fd = r->comp->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 0) <= 0 || (pfd.revents & POLLIN) == 0)
        return;
    for (;;) {
        struct ibv_cq *cq = NULL;
        void *ctx = NULL;
        if (ibv_get_cq_event(r->comp, &cq, &ctx) != 0)
            break;
        ibv_ack_cq_events(cq, 1);
    }
    ibv_req_notify_cq(r->cq, 0);
}

static int poll_cq(struct ps_rdma *r, struct ps_rdma_event *ev, int *n, int max, unsigned *budget)
{
    if (!r->cq)
        return 0;
    drain_notify(r);
    struct ibv_wc wc[16];
    while (*budget > 0 && *n < max) {
        int want = 16;
        if ((unsigned)want > *budget)
            want = (int)*budget;
        if (want > max - *n)
            want = max - *n;
        if (want < 1)
            break;
        int got = ibv_poll_cq(r->cq, want, wc);
        if (got == 0)
            break;
        if (got < 0) {
            ps_notice("rdma poll cq failed");
            return -1;
        }
        for (int i = 0; i < got; i++) {
            (*budget)--;
            unsigned kind = 0;
            unsigned lane = 0;
            unsigned slot = 0;
            unpack_wr(wc[i].wr_id, &kind, &lane, &slot);
            if (lane >= PS_MAX_SUBFLOWS) {
                ps_notice("rdma completion for an unknown lane");
                return emit(ev, n, max, PS_RDMA_EV_ERROR, 0, NULL, 0, 0);
            }
            struct rdma_lane *ln = &r->lanes[lane];
            if (wc[i].status != IBV_WC_SUCCESS) {
                ps_notice("rdma completion status %s lane %u", ibv_wc_status_str(wc[i].status), lane);
                ln->state = LANE_DEAD;
                if (kind == 1 && slot < 256)
                    ln->send_used[slot] = 0;
                return emit(ev, n, max, PS_RDMA_EV_ERROR, lane, NULL, 0, 0);
            }
            if (kind == 1) {
                if (slot < 256)
                    ln->send_used[slot] = 0;
                continue;
            }
            if (kind != 2 || slot >= r->recv_depth || !ln->mem) {
                ln->state = LANE_DEAD;
                return emit(ev, n, max, PS_RDMA_EV_ERROR, lane, NULL, 0, 0);
            }
            ln->recv_held[slot] = 1;
            const uint8_t *data = ln->mem + ln->stride * (r->send_depth + slot);
            if (emit(ev, n, max, PS_RDMA_EV_RECV, lane, data, wc[i].byte_len, slot) != 0)
                return -1;
        }
    }
    return 0;
}

int ps_rdma_available(void)
{
    return 1;
}

static socklen_t copy_addr(const struct sockaddr *src, socklen_t srclen, struct sockaddr_storage *dst)
{
    memset(dst, 0, sizeof(*dst));
    if (!src || srclen <= 0 || (size_t)srclen > sizeof(*dst))
        return 0;
    memcpy(dst, src, (size_t)srclen);
    if (dst->ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)dst;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            struct sockaddr_in in4;
            memset(&in4, 0, sizeof(in4));
            in4.sin_family = AF_INET;
            memcpy(&in4.sin_addr, in6->sin6_addr.s6_addr + 12, 4);
            in4.sin_port = in6->sin6_port;
            memset(dst, 0, sizeof(*dst));
            memcpy(dst, &in4, sizeof(in4));
            return (socklen_t)sizeof(in4);
        }
    }
    return srclen;
}

static void format_addr(const struct sockaddr *sa, char *out, size_t n)
{
    if (!out || n == 0)
        return;
    out[0] = '\0';
    const void *ip = NULL;
    int fam = sa ? sa->sa_family : AF_UNSPEC;
    if (fam == AF_INET)
        ip = &((const struct sockaddr_in *)sa)->sin_addr;
    else if (fam == AF_INET6)
        ip = &((const struct sockaddr_in6 *)sa)->sin6_addr;
    if (!ip || !inet_ntop(fam, ip, out, (socklen_t)n))
        snprintf(out, n, "unknown");
}

static int bind_listen(struct ps_rdma *r, struct sockaddr *addr)
{
    if (rdma_bind_addr(r->listen, addr) != 0)
        return -1;
    if (rdma_listen(r->listen, 16) != 0)
        return -1;
    return 0;
}

static int reset_listen(struct ps_rdma *r)
{
    if (r->listen) {
        rdma_destroy_id(r->listen);
        r->listen = NULL;
    }
    return rdma_create_id(r->ec, &r->listen, r, RDMA_PS_TCP);
}

struct ps_rdma *ps_rdma_open(const struct ps_rdma_cfg *cfg, uint16_t *listen_port)
{
    if (!cfg || !depth_ok(cfg->send_depth, cfg->recv_depth, cfg->max_lanes, cfg->message_bytes))
        return NULL;
    if (cfg->is_server && !listen_port)
        return NULL;
    struct ps_rdma *r = (struct ps_rdma *)calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    pthread_mutex_init(&r->mu, NULL);
    r->is_server = cfg->is_server ? 1 : 0;
    r->send_depth = cfg->send_depth;
    r->recv_depth = cfg->recv_depth;
    r->max_lanes = cfg->max_lanes;
    r->message_bytes = cfg->message_bytes;
    if (cfg->device && cfg->device[0])
        r->device = strdup(cfg->device);
    r->ec = rdma_create_event_channel();
    if (!r->ec) {
        ps_notice("rdma event channel failed: %s", strerror(errno));
        ps_rdma_close(r);
        return NULL;
    }
    /* The CM channel stays blocking. librdmacm reads a fixed-size event, and
       O_NONBLOCK makes bind and resolve fail with EAGAIN. Callers poll first. */
    if (!cfg->is_server)
        return r;
    if (rdma_create_id(r->ec, &r->listen, r, RDMA_PS_TCP) != 0) {
        ps_notice("rdma listen id failed: %s", strerror(errno));
        ps_rdma_close(r);
        return NULL;
    }
    struct sockaddr_storage chosen;
    memset(&chosen, 0, sizeof(chosen));
    socklen_t chosen_len = 0;
    int bound = 0;
    if (cfg->bind_addr && cfg->bind_len > 0) {
        chosen_len = copy_addr(cfg->bind_addr, cfg->bind_len, &chosen);
        if (chosen_len > 0) {
            ps_addr_set_port((struct sockaddr *)&chosen, chosen_len, 0);
            if (bind_listen(r, (struct sockaddr *)&chosen) == 0) {
                bound = 1;
            } else {
                char text[64];
                format_addr((struct sockaddr *)&chosen, text, sizeof(text));
                ps_notice("rdma bind %s failed: %s", text, strerror(errno));
                if (reset_listen(r) != 0) {
                    ps_notice("rdma listen id failed: %s", strerror(errno));
                    ps_rdma_close(r);
                    return NULL;
                }
            }
        }
    }
    if (!bound) {
        struct sockaddr_storage any;
        memset(&any, 0, sizeof(any));
        int fam = chosen_len > 0 ? chosen.ss_family : AF_INET;
        if (fam == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&any;
            in6->sin6_family = AF_INET6;
            in6->sin6_addr = in6addr_any;
        } else {
            struct sockaddr_in *in4 = (struct sockaddr_in *)&any;
            in4->sin_family = AF_INET;
            in4->sin_addr.s_addr = htonl(INADDR_ANY);
        }
        if (bind_listen(r, (struct sockaddr *)&any) != 0) {
            ps_notice("rdma listen failed: %s", strerror(errno));
            ps_rdma_close(r);
            return NULL;
        }
        memcpy(&chosen, &any, sizeof(any));
    }
    *listen_port = ntohs(rdma_get_src_port(r->listen));
    char text[64];
    format_addr((struct sockaddr *)&chosen, text, sizeof(text));
    ps_notice("rdma listening on %s port %u", text, *listen_port);
    return r;
}

void ps_rdma_close(struct ps_rdma *rdma)
{
    if (!rdma)
        return;
    pthread_mutex_lock(&rdma->mu);
    rdma->closing = 1;
    for (unsigned i = 0; i < PS_MAX_SUBFLOWS; i++) {
        struct rdma_lane *ln = &rdma->lanes[i];
        if (ln->id) {
            if (ln->qp)
                rdma_destroy_qp(ln->id);
            rdma_destroy_id(ln->id);
            ln->id = NULL;
            ln->qp = 0;
        }
        free_lane_buffers(ln);
    }
    if (rdma->listen) {
        rdma_destroy_id(rdma->listen);
        rdma->listen = NULL;
    }
    if (rdma->cq) {
        ibv_destroy_cq(rdma->cq);
        rdma->cq = NULL;
    }
    if (rdma->comp) {
        ibv_destroy_comp_channel(rdma->comp);
        rdma->comp = NULL;
    }
    if (rdma->pd) {
        ibv_dealloc_pd(rdma->pd);
        rdma->pd = NULL;
    }
    if (rdma->ec) {
        rdma_destroy_event_channel(rdma->ec);
        rdma->ec = NULL;
    }
    pthread_mutex_unlock(&rdma->mu);
    pthread_mutex_destroy(&rdma->mu);
    free(rdma->device);
    free(rdma);
}

int ps_rdma_fds(struct ps_rdma *rdma, int *fds, int max)
{
    if (!rdma || !fds || max <= 0)
        return 0;
    pthread_mutex_lock(&rdma->mu);
    int n = 0;
    if (rdma->ec && rdma->ec->fd >= 0 && n < max)
        fds[n++] = rdma->ec->fd;
    if (rdma->comp && rdma->comp->fd >= 0 && n < max)
        fds[n++] = rdma->comp->fd;
    pthread_mutex_unlock(&rdma->mu);
    return n;
}

int ps_rdma_authorize(struct ps_rdma *rdma, uint32_t lane, const uint8_t token[32])
{
    if (!rdma || !token || lane >= PS_MAX_SUBFLOWS)
        return -1;
    pthread_mutex_lock(&rdma->mu);
    struct rdma_lane *ln = &rdma->lanes[lane];
    int rc = -1;
    if (ln->state == LANE_FREE || ln->state == LANE_AUTH) {
        memcpy(ln->token, token, 32);
        ln->state = LANE_AUTH;
        rc = 0;
    }
    pthread_mutex_unlock(&rdma->mu);
    return rc;
}

int ps_rdma_connect(struct ps_rdma *rdma, uint32_t lane, const struct sockaddr *peer,
                    socklen_t peer_len, const uint8_t token[32])
{
    if (!rdma || !peer || !token || lane >= PS_MAX_SUBFLOWS || peer_len <= 0)
        return -1;
    pthread_mutex_lock(&rdma->mu);
    struct rdma_lane *ln = &rdma->lanes[lane];
    int rc = -1;
    if (ln->state != LANE_FREE) {
        pthread_mutex_unlock(&rdma->mu);
        return -1;
    }
    memcpy(ln->token, token, 32);
    if (rdma_create_id(rdma->ec, &ln->id, rdma, RDMA_PS_TCP) != 0) {
        ps_notice("rdma id failed: %s", strerror(errno));
        ln->state = LANE_DEAD;
        pthread_mutex_unlock(&rdma->mu);
        return -1;
    }
    struct sockaddr_storage dest;
    socklen_t dest_len = copy_addr(peer, peer_len, &dest);
    ln->state = LANE_RESOLVE;
    if (dest_len == 0 || rdma_resolve_addr(ln->id, NULL, (struct sockaddr *)&dest, 2000) != 0) {
        ps_notice("rdma resolve addr failed: %s", strerror(errno));
        ln->state = LANE_DEAD;
    } else {
        rc = 0;
    }
    pthread_mutex_unlock(&rdma->mu);
    return rc;
}

int ps_rdma_progress(struct ps_rdma *rdma, struct ps_rdma_event *ev, int max, unsigned budget)
{
    if (!rdma || !ev || max <= 0)
        return -1;
    if (budget == 0)
        budget = 1;
    pthread_mutex_lock(&rdma->mu);
    int n = 0;
    int rc = 0;
    if (!rdma->closing) {
        rc = poll_cm(rdma, ev, &n, max);
        if (rc == 0)
            rc = poll_cq(rdma, ev, &n, max, &budget);
    }
    pthread_mutex_unlock(&rdma->mu);
    return rc == 0 ? n : -1;
}

int ps_rdma_send(struct ps_rdma *rdma, uint32_t lane, const void *data, size_t len)
{
    if (!rdma || !data || lane >= PS_MAX_SUBFLOWS || len == 0 || len > rdma->message_bytes)
        return -1;
    pthread_mutex_lock(&rdma->mu);
    struct rdma_lane *ln = &rdma->lanes[lane];
    int rc = -1;
    if (ln->state == LANE_UP && ln->qp && ln->buffers) {
        unsigned slot = rdma->send_depth;
        for (unsigned i = 0; i < rdma->send_depth; i++) {
            if (!ln->send_used[i]) {
                slot = i;
                break;
            }
        }
        if (slot == rdma->send_depth) {
            rc = 1;
        } else {
            uint8_t *dst = ln->mem + ln->stride * slot;
            memcpy(dst, data, len);
            struct ibv_sge sge;
            memset(&sge, 0, sizeof(sge));
            sge.addr = (uintptr_t)dst;
            sge.length = (uint32_t)len;
            sge.lkey = ln->mrs[slot]->lkey;
            struct ibv_send_wr wr;
            struct ibv_send_wr *bad = NULL;
            memset(&wr, 0, sizeof(wr));
            wr.wr_id = pack_wr(1, lane, slot);
            wr.sg_list = &sge;
            wr.num_sge = 1;
            wr.opcode = IBV_WR_SEND;
            wr.send_flags = IBV_SEND_SIGNALED;
            if (ibv_post_send(ln->id->qp, &wr, &bad) != 0) {
                ps_notice("rdma post send failed: %s", strerror(errno));
                ln->state = LANE_DEAD;
                rc = -1;
            } else {
                ln->send_used[slot] = 1;
                rc = 0;
            }
        }
    }
    pthread_mutex_unlock(&rdma->mu);
    return rc;
}

int ps_rdma_recycle(struct ps_rdma *rdma, uint32_t lane, unsigned slot)
{
    if (!rdma || lane >= PS_MAX_SUBFLOWS)
        return -1;
    pthread_mutex_lock(&rdma->mu);
    struct rdma_lane *ln = &rdma->lanes[lane];
    int rc = -1;
    if (slot < rdma->recv_depth && ln->recv_held[slot] && ln->state != LANE_DEAD && ln->qp) {
        rc = post_recv_slot(rdma, ln, slot);
        if (rc != 0)
            ln->state = LANE_DEAD;
    }
    pthread_mutex_unlock(&rdma->mu);
    return rc;
}

#else

int ps_rdma_available(void)
{
    return 0;
}

struct ps_rdma *ps_rdma_open(const struct ps_rdma_cfg *cfg, uint16_t *listen_port)
{
    (void)cfg;
    (void)listen_port;
    return NULL;
}

void ps_rdma_close(struct ps_rdma *rdma)
{
    (void)rdma;
}

int ps_rdma_fds(struct ps_rdma *rdma, int *fds, int max)
{
    (void)rdma;
    (void)fds;
    (void)max;
    return 0;
}

int ps_rdma_authorize(struct ps_rdma *rdma, uint32_t lane, const uint8_t token[32])
{
    (void)rdma;
    (void)lane;
    (void)token;
    return -1;
}

int ps_rdma_connect(struct ps_rdma *rdma, uint32_t lane, const struct sockaddr *peer,
                    socklen_t peer_len, const uint8_t token[32])
{
    (void)rdma;
    (void)lane;
    (void)peer;
    (void)peer_len;
    (void)token;
    return -1;
}

int ps_rdma_progress(struct ps_rdma *rdma, struct ps_rdma_event *ev, int max, unsigned budget)
{
    (void)rdma;
    (void)ev;
    (void)max;
    (void)budget;
    return -1;
}

int ps_rdma_send(struct ps_rdma *rdma, uint32_t lane, const void *data, size_t len)
{
    (void)rdma;
    (void)lane;
    (void)data;
    (void)len;
    return -1;
}

int ps_rdma_recycle(struct ps_rdma *rdma, uint32_t lane, unsigned slot)
{
    (void)rdma;
    (void)lane;
    (void)slot;
    return -1;
}

int ps_rdma_clamp_depths(size_t message, unsigned lanes, unsigned *send_depth, unsigned *recv_depth,
                         int quiet)
{
    (void)message;
    (void)lanes;
    (void)send_depth;
    (void)recv_depth;
    (void)quiet;
    return 0;
}

#endif

int ps_rdma_supported(void)
{
    return ps_rdma_available();
}
