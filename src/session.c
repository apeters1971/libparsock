#include "session.h"

#include "autoscale.h"
#include "clock.h"
#include "crypto.h"
#include "discover.h"
#include "endian.h"
#include "log.h"
#include "net.h"
#include "reassembly.h"
#include "spt_wire.h"
#include "tls.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/uio.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#define ACT_MAX 48
#define RX_PIPELINE 256
/* One context per in-flight record. A context is not shared across workers. */
#define SF_AEAD_SLOTS 64
#define RX_BYTES (4u * 1024u * 1024u)
#define FLUSH_IOV 16

enum {
    ACT_IO = 1,
    ACT_STOP,
    ACT_READABLE,
    ACT_WRITABLE,
    ACT_ERROR,
    ACT_REGISTER,
    ACT_POKE
};

enum {
    SF_UNUSED = 0,
    SF_OPEN_SENT,
    SF_WAIT_TCP,
    SF_JOINING,
    SF_ACTIVE,
    SF_DRAINING,
    SF_RETIRED
};

struct buf {
    uint8_t *p;
    size_t len;
    size_t off;
    size_t cap;
};

struct action {
    int type;
    int fd;
    int rd;
    int wr;
    int err;
    uint8_t sid[32];
};

struct wire_slot {
    uint64_t seq;
    int ready;
    int ok;
    uint8_t *frame;
    size_t len;
    size_t off;
    struct wire_slot *next;
};

struct frame_cache {
    struct frame_cache *next;
};

struct plain_slot {
    int ready;
    int ok;
    struct spt_header hdr;
    uint8_t *plain;
    size_t plain_cap;
    struct plain_slot *next;
};

struct crypto_job {
    int op_open;
    int mac;
    uint16_t alg;
    uint8_t key[SPT_KEY_LEN];
    uint8_t iv[SPT_IV_LEN];
    uint64_t seq;
    uint8_t aad[SPT_FRAME_HEADER_LEN];
    const uint8_t *copy_src;
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    uint8_t tag_store[SPT_TAG_LEN];
    uint8_t *tag;
    struct wire_slot *wslot;
    struct plain_slot *pslot;
    struct subflow *sf;
    struct crypto_job *next;
    EVP_CIPHER_CTX *aead_ctx;
    int aead_owned;
    int aead_slot;
    int keep_in;
};

struct gen_mat {
    int valid;
    uint32_t generation;
    uint8_t send_key[SPT_KEY_LEN];
    uint8_t send_iv[SPT_IV_LEN];
    uint8_t recv_key[SPT_KEY_LEN];
    uint8_t recv_iv[SPT_IV_LEN];
    uint8_t send_mac[SPT_KEY_LEN];
    uint8_t recv_mac[SPT_KEY_LEN];
};

struct subflow {
    int used;
    int state;
    int fd;
    int connecting;
    int need_connect;
    int close_pending;
    int drain;
    int end_sent;
    int end_recv;
    int counted_active;
    int keys_ready;
    int server_nonce_set;
    int want_read;
    int want_write;
    int read_paused;
    int rekey_wait;
    int local_announced;
    int remote_rekey;
    uint32_t id;
    uint32_t send_gen;
    uint32_t recv_gen;
    uint32_t rekey_target;
    uint64_t send_seq;
    uint64_t parse_seq;
    uint8_t client_nonce[SPT_NONCE_LEN];
    uint8_t server_nonce[SPT_NONCE_LEN];
    struct gen_mat gens[2];
    struct wire_slot *out_head;
    struct wire_slot *out_tail;
    size_t out_bytes;
    uint8_t preface[SPT_PREFACE_LEN];
    size_t preface_len;
    size_t preface_off;
    uint8_t *rx;
    size_t rx_off;
    size_t rx_len;
    size_t rx_cap;
    struct plain_slot *in_head;
    struct plain_slot *in_tail;
    unsigned in_flight;
    EVP_CIPHER_CTX *seal_ctx[SF_AEAD_SLOTS];
    EVP_CIPHER_CTX *open_ctx[SF_AEAD_SLOTS];
    uint64_t seal_busy;
    uint64_t open_busy;
};

struct ps_session {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    pthread_mutex_t job_mu;
    pthread_cond_t job_cv;
    int refs;
    int is_server;
    int state;
    int err;
    int closing;
    int failed_latched;
    int in_fail;
    int hs_done;
    int send_fin;
    int eos_pending;
    int got_eos;
    int in_user_read;
    int rx_hold;
    int send_hold;
    int send_stalled;
    int need_export;
    int root_valid;
    int registered;
    int unregistered;
    int poke_pending;
    int dispatching;
    int dispatch_again;
    pthread_t dispatch_owner;
    int workers_stopped;
    int stop_workers;
    unsigned nworkers;
    pthread_t *tids;
    ps_scale_mode_t scale_mode;
    unsigned min_sockets;
    unsigned max_sockets;
    unsigned initial_sockets;
    unsigned proposed;
    unsigned expect;
    unsigned n_active;
    uint32_t scale_interval_ms;
    uint64_t min_transfer_size;
    size_t frame_size;
    size_t recv_window;
    size_t sf_hi;
    struct frame_cache *frames;
    unsigned nframes;
    size_t max_poller_bytes;
    unsigned max_poller_records;
    uint16_t aead;
    uint8_t min_protection;
    uint8_t peer_min;
    int have_peer_protection;
    int protection_sent;
    uint32_t connect_timeout_ms;
    uint32_t io_timeout_ms;
    uint16_t data_port;
    int ctrl_fd;
    int ctrl_want_read;
    int ctrl_want_write;
    SSL *ssl;
    SSL_CTX *ctx;
    char *server_name;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    uint8_t client_random[SPT_RANDOM_LEN];
    uint8_t server_random[SPT_RANDOM_LEN];
    uint8_t session_id[SPT_SESSION_ID_LEN];
    uint8_t hello_hash[SPT_HASH_LEN];
    uint8_t client_hello[SPT_CLIENT_HELLO_LEN];
    uint8_t server_hello[SPT_SERVER_HELLO_LEN];
    int have_client_hello;
    int have_server_hello;
    uint8_t root[SPT_ROOT_LEN];
    struct buf cin;
    struct buf cout;
    struct subflow sf[PS_MAX_SUBFLOWS];
    uint32_t sf_count;
    unsigned rr;
    uint64_t send_off;
    uint64_t send_limit;
    uint64_t advertised;
    uint64_t eos_off;
    struct spt_reassembly reassembly;
    struct action acts[ACT_MAX];
    int nacts;
    struct crypto_job *inline_head;
    struct crypto_job *inline_tail;
    struct crypto_job *job_head;
    struct crypto_job *job_tail;
    unsigned jobs_inflight;
    ps_io_cbs io;
    struct ps_session_hooks hooks;
    struct ps_scale_state scale;
    int scale_inited;
    uint64_t last_scale_ms;
    uint64_t byte_mark;
    uint64_t goodput_bps;
    uint32_t rtt_us;
    uint32_t rtt_min;
    uint64_t retrans_mark;
    uint32_t peer_scale;
    unsigned last_hint;
    uint64_t app_tx;
    uint64_t app_rx;
    uint64_t records_tx;
    uint64_t records_rx;
    struct ps_hwinfo hw;
};

static void fail_locked(struct ps_session *s, int err);
static int queue_ctrl_locked(struct ps_session *s, uint16_t type,
                             const uint8_t *body, size_t len);
static void refresh_write_locked(struct ps_session *s, struct subflow *sf);
static int enqueue_record_locked(struct ps_session *s, struct subflow *sf,
                                 uint8_t type, uint16_t flags, uint64_t logical,
                                 const uint8_t *plain, uint32_t plain_len,
                                 uint8_t protection);
static void send_eos_locked(struct ps_session *s);
static void send_protection_locked(struct ps_session *s);
static void apply_sf_locked(struct ps_session *s, struct subflow *sf);
static void apply_all_locked(struct ps_session *s);
static void dispatch(struct ps_session *s);

static void lock_s(struct ps_session *s) { pthread_mutex_lock(&s->mu); }
static void unlock_s(struct ps_session *s) { pthread_mutex_unlock(&s->mu); }

static int deadline_reached(const struct timespec *deadline)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    if (now.tv_sec != deadline->tv_sec)
        return now.tv_sec > deadline->tv_sec;
    return now.tv_nsec >= deadline->tv_nsec;
}

static int buf_append(struct buf *b, const void *data, size_t n)
{
    if (n == 0)
        return 0;
    if (b->off > 0 && b->off == b->len) {
        b->off = 0;
        b->len = 0;
    }
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->len + n) {
            if (nc > (SIZE_MAX / 2))
                return -1;
            nc *= 2;
        }
        uint8_t *np = (uint8_t *)realloc(b->p, nc);
        if (!np)
            return -1;
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return 0;
}

static void buf_consume(struct buf *b, size_t n)
{
    if (n > b->len - b->off)
        n = b->len - b->off;
    b->off += n;
    if (b->off == b->len) {
        b->off = 0;
        b->len = 0;
    } else if (b->off > 4096) {
        memmove(b->p, b->p + b->off, b->len - b->off);
        b->len -= b->off;
        b->off = 0;
    }
}

static void buf_free(struct buf *b)
{
    free(b->p);
    memset(b, 0, sizeof(*b));
}

static char *dupstr(const char *s)
{
    if (!s)
        return NULL;
    size_t n = strlen(s);
    char *d = (char *)malloc(n + 1);
    if (!d)
        return NULL;
    memcpy(d, s, n + 1);
    return d;
}

static void queue_act(struct ps_session *s, const struct action *a)
{
    if (s->nacts >= ACT_MAX) {
        s->poke_pending = 1;
        return;
    }
    s->acts[s->nacts++] = *a;
    if (a->type == ACT_POKE)
        s->poke_pending = 1;
}

static void queue_io(struct ps_session *s, int fd, int rd, int wr)
{
    struct action a;
    memset(&a, 0, sizeof(a));
    a.type = ACT_IO;
    a.fd = fd;
    a.rd = rd;
    a.wr = wr;
    queue_act(s, &a);
}

static void queue_poke(struct ps_session *s)
{
    s->poke_pending = 1;
    struct action a;
    memset(&a, 0, sizeof(a));
    a.type = ACT_POKE;
    queue_act(s, &a);
}

static int spt_err_code(int err)
{
    switch (err) {
    case PS_ERR_AUTH: return SPT_E_AUTH;
    case PS_ERR_CRYPTO: return SPT_E_CRYPTO;
    case PS_ERR_FLOW: return SPT_E_FLOW;
    case PS_ERR_LIMIT: return SPT_E_LIMIT;
    case PS_ERR_CLOSED: return SPT_E_CLOSED;
    case PS_ERR_NOMEM: return SPT_E_INTERNAL;
    default: return SPT_E_PROTO;
    }
}

static void fail_locked(struct ps_session *s, int err)
{
    if (s->state == PS_STATE_FAILED || s->state == PS_STATE_CLOSED || s->in_fail)
        return;
    s->in_fail = 1;
    s->state = PS_STATE_FAILED;
    s->err = err ? err : PS_ERR_PROTO;
    ps_log("session failed: %s", ps_strerror(s->err));
    if (s->hs_done && s->ctrl_fd >= 0) {
        uint8_t body[4];
        ps_put_u32(body, (uint32_t)spt_err_code(s->err));
        queue_ctrl_locked(s, SPT_CTRL_ERROR, body, sizeof(body));
    }
    pthread_cond_broadcast(&s->cv);
    struct action a;
    memset(&a, 0, sizeof(a));
    a.type = ACT_ERROR;
    a.err = s->err;
    queue_act(s, &a);
}

static int queue_ctrl_locked(struct ps_session *s, uint16_t type,
                             const uint8_t *body, size_t len)
{
    uint8_t frame[512];
    if (len > sizeof(frame) - 8)
        return -1;
    size_t n = 0;
    if (spt_ctrl_encode(frame, sizeof(frame), type, body, len, &n) != 0)
        return -1;
    if (buf_append(&s->cout, frame, n) != 0) {
        fail_locked(s, PS_ERR_NOMEM);
        return -1;
    }
    s->ctrl_want_write = 1;
    if (s->ctrl_fd >= 0)
        queue_io(s, s->ctrl_fd, s->ctrl_want_read, 1);
    else
        queue_poke(s);
    return 0;
}

static struct subflow *sf_by_id(struct ps_session *s, uint32_t id)
{
    if (id >= s->sf_count || !s->sf[id].used)
        return NULL;
    return &s->sf[id];
}

static struct subflow *sf_by_fd(struct ps_session *s, int fd)
{
    for (uint32_t i = 0; i < s->sf_count; i++) {
        if (s->sf[i].used && s->sf[i].fd == fd)
            return &s->sf[i];
    }
    return NULL;
}

static struct gen_mat *gen_lookup(struct subflow *sf, uint32_t generation)
{
    for (int i = 0; i < 2; i++) {
        if (sf->gens[i].valid && sf->gens[i].generation == generation)
            return &sf->gens[i];
    }
    return NULL;
}

static struct gen_mat *alloc_gen(struct ps_session *s, struct subflow *sf, uint32_t generation)
{
    struct gen_mat *existing = gen_lookup(sf, generation);
    if (existing)
        return existing;
    if (!s->root_valid)
        return NULL;
    int slot = -1;
    for (int i = 0; i < 2; i++) {
        if (!sf->gens[i].valid) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < 2; i++) {
            if (sf->gens[i].generation != sf->send_gen &&
                sf->gens[i].generation != sf->recv_gen) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0)
        slot = 0;
    struct gen_mat *g = &sf->gens[slot];
    OPENSSL_cleanse(g, sizeof(*g));
    g->generation = generation;
    uint8_t send_dir = s->is_server ? SPT_DIR_S2C : SPT_DIR_C2S;
    uint8_t recv_dir = s->is_server ? SPT_DIR_C2S : SPT_DIR_S2C;
    if (spt_derive_aead_key(s->root, send_dir, sf->id, generation, s->aead,
                            sf->client_nonce, sf->server_nonce, s->session_id,
                            g->send_key, g->send_iv) != 0)
        return NULL;
    if (spt_derive_aead_key(s->root, recv_dir, sf->id, generation, s->aead,
                            sf->client_nonce, sf->server_nonce, s->session_id,
                            g->recv_key, g->recv_iv) != 0)
        return NULL;
    if (spt_derive_mac_key(s->root, send_dir, sf->id, generation, SPT_MAC_HMAC_SHA256,
                           sf->client_nonce, sf->server_nonce, s->session_id,
                           g->send_mac) != 0)
        return NULL;
    if (spt_derive_mac_key(s->root, recv_dir, sf->id, generation, SPT_MAC_HMAC_SHA256,
                           sf->client_nonce, sf->server_nonce, s->session_id,
                           g->recv_mac) != 0)
        return NULL;
    g->valid = 1;
    return g;
}

static int ensure_keys_locked(struct ps_session *s, struct subflow *sf)
{
    if (sf->keys_ready)
        return 0;
    if (!s->root_valid || !sf->server_nonce_set)
        return -1;
    if (!alloc_gen(s, sf, 0))
        return -1;
    sf->keys_ready = 1;
    return 0;
}

static int sf_alloc_rx(struct ps_session *s, struct subflow *sf)
{
    if (sf->rx)
        return 0;
    sf->rx_cap = spt_frame_wire_len((uint32_t)s->frame_size);
    if (sf->rx_cap < RX_BYTES)
        sf->rx_cap = RX_BYTES;
    sf->rx = (uint8_t *)malloc(sf->rx_cap);
    if (!sf->rx)
        return -1;
    return 0;
}

static void refresh_write_locked(struct ps_session *s, struct subflow *sf)
{
    int ready = 0;
    if (sf->connecting)
        ready = 1;
    else if (sf->preface_off < sf->preface_len)
        ready = 1;
    else if (sf->out_head && sf->out_head->ready && sf->out_head->ok)
        ready = 1;
    int changed = sf->want_write != ready;
    sf->want_write = ready;
    if (sf->fd >= 0 && changed)
        queue_io(s, sf->fd, sf->want_read, sf->want_write);
}

/* Caller holds the session lock. Returns a context owned by this socket. */
static EVP_CIPHER_CTX *sf_take_aead(struct subflow *sf, int open, int *slot, int *owned)
{
    EVP_CIPHER_CTX **pool = open ? sf->open_ctx : sf->seal_ctx;
    uint64_t *busy = open ? &sf->open_busy : &sf->seal_busy;
    for (int i = 0; i < SF_AEAD_SLOTS; i++) {
        if (*busy & (1ull << i))
            continue;
        if (!pool[i]) {
            pool[i] = spt_aead_ctx_new();
            if (!pool[i])
                return NULL;
        }
        *busy |= (1ull << i);
        *slot = i;
        *owned = 0;
        return pool[i];
    }
    *slot = -1;
    *owned = 1;
    return spt_aead_ctx_new();
}

/* Caller holds the session lock, or is the last thread left in session_destroy. */
static void release_aead(struct crypto_job *job)
{
    if (!job || !job->aead_ctx)
        return;
    if (job->aead_owned) {
        spt_aead_ctx_free(job->aead_ctx);
    } else if (job->sf && job->aead_slot >= 0 && job->aead_slot < SF_AEAD_SLOTS) {
        uint64_t *busy = job->op_open ? &job->sf->open_busy : &job->sf->seal_busy;
        *busy &= ~(1ull << job->aead_slot);
    }
    job->aead_ctx = NULL;
}

static void free_job(struct crypto_job *job)
{
    if (!job)
        return;
    release_aead(job);
    if (job->in && !job->keep_in) {
        OPENSSL_cleanse(job->in, job->in_len ? job->in_len : 1);
        free(job->in);
    }
    OPENSSL_cleanse(job->key, sizeof(job->key));
    free(job);
}

static int execute_job(struct crypto_job *job)
{
    const uint8_t *in = job->in_len ? job->in : NULL;
    if (!job->aead_ctx)
        return -1;
    if (job->mac) {
        if (job->op_open) {
            return spt_aead_open_ctx(job->aead_ctx, job->alg, job->key, job->iv, job->seq, job->aad,
                                     in, job->in_len, job->tag, NULL);
        }
        return spt_aead_seal_ctx(job->aead_ctx, job->alg, job->key, job->iv, job->seq, job->aad,
                                 in, job->in_len, NULL, job->tag);
    }
    if (job->op_open) {
        return spt_aead_open_ctx(job->aead_ctx, job->alg, job->key, job->iv, job->seq, job->aad,
                                 in, job->in_len, job->tag, job->out);
    }
    return spt_aead_seal_ctx(job->aead_ctx, job->alg, job->key, job->iv, job->seq, job->aad,
                             in, job->in_len, job->out, job->tag);
}

static void submit_batch_locked(struct ps_session *s,
                                struct crypto_job *head,
                                struct crypto_job *tail,
                                unsigned count)
{
    if (!head)
        return;
    if (s->nworkers == 0 || s->workers_stopped) {
        if (s->inline_tail)
            s->inline_tail->next = head;
        else
            s->inline_head = head;
        s->inline_tail = tail;
        return;
    }
    pthread_mutex_lock(&s->job_mu);
    if (s->job_tail)
        s->job_tail->next = head;
    else
        s->job_head = head;
    s->job_tail = tail;
    if (count > 1)
        pthread_cond_broadcast(&s->job_cv);
    else
        pthread_cond_signal(&s->job_cv);
    pthread_mutex_unlock(&s->job_mu);
}

static void submit_job_locked(struct ps_session *s, struct crypto_job *job)
{
    s->jobs_inflight++;
    job->next = NULL;
    submit_batch_locked(s, job, job, 1);
}

static void finish_job_locked(struct ps_session *s, struct crypto_job *job, int ok)
{
    if (s->jobs_inflight)
        s->jobs_inflight--;
    if (job->op_open) {
        if (job->pslot) {
            job->pslot->ready = 1;
            job->pslot->ok = ok == 0;
        }
        if (job->sf && job->sf->in_flight)
            job->sf->in_flight--;
        if (ok != 0)
            fail_locked(s, PS_ERR_CRYPTO);
        if (job->sf && job->sf->read_paused && job->sf->in_flight <= RX_PIPELINE / 2 &&
            job->sf->fd >= 0 && job->sf->state != SF_RETIRED) {
            job->sf->read_paused = 0;
            job->sf->want_read = 1;
            queue_io(s, job->sf->fd, 1, job->sf->want_write);
        }
    } else if (job->wslot) {
        job->wslot->ready = 1;
        job->wslot->ok = ok == 0;
        if (ok != 0)
            fail_locked(s, PS_ERR_CRYPTO);
        else if (job->sf)
            refresh_write_locked(s, job->sf);
    }
}

static void *worker_main(void *arg)
{
    struct ps_session *s = (struct ps_session *)arg;
    for (;;) {
        pthread_mutex_lock(&s->job_mu);
        while (!s->stop_workers && !s->job_head)
            pthread_cond_wait(&s->job_cv, &s->job_mu);
        if (s->stop_workers && !s->job_head) {
            pthread_mutex_unlock(&s->job_mu);
            break;
        }
        struct crypto_job *job = s->job_head;
        s->job_head = job->next;
        if (!s->job_head)
            s->job_tail = NULL;
        pthread_mutex_unlock(&s->job_mu);
        int ok = execute_job(job);
        int opened = job->op_open;
        lock_s(s);
        finish_job_locked(s, job, ok);
        if (opened && s->state != PS_STATE_FAILED)
            apply_sf_locked(s, job->sf);
        release_aead(job);
        int need_dispatch = s->nacts > 0 || s->poke_pending;
        unlock_s(s);
        free_job(job);
        if (need_dispatch)
            dispatch(s);
    }
    return NULL;
}

/* Caller holds the session lock. Full-size data frames are reused so the
   send path does not page-fault a fresh buffer on every record. */
static uint8_t *frame_get_locked(struct ps_session *s, size_t wire)
{
    size_t full = spt_frame_wire_len((uint32_t)s->frame_size);
    if (wire == full && s->frames) {
        struct frame_cache *n = s->frames;
        s->frames = n->next;
        if (s->nframes)
            s->nframes--;
        return (uint8_t *)n;
    }
    return (uint8_t *)malloc(wire);
}

static void frame_put_locked(struct ps_session *s, uint8_t *frame, size_t wire)
{
    size_t full = spt_frame_wire_len((uint32_t)s->frame_size);
    if (frame && wire == full && s->nframes < 1024) {
        struct frame_cache *n = (struct frame_cache *)frame;
        n->next = s->frames;
        s->frames = n;
        s->nframes++;
        return;
    }
    free(frame);
}

static int enqueue_record_batch_locked(struct ps_session *s, struct subflow *sf,
                                       uint8_t type, uint16_t flags, uint64_t logical,
                                       const uint8_t *plain, uint32_t plain_len,
                                       uint8_t protection,
                                       struct crypto_job **batch_head,
                                       struct crypto_job **batch_tail,
                                       unsigned *batch_count)
{
    if (sf->send_seq >= SPT_REKEY_RECORD_LIMIT) {
        fail_locked(s, PS_ERR_LIMIT);
        return -1;
    }
    if (protection != SPT_PROTECTION_CONFIDENTIAL &&
        protection != SPT_PROTECTION_AUTHENTICATED) {
        fail_locked(s, PS_ERR_PROTO);
        return -1;
    }
    if (type != SPT_REC_DATA && protection != SPT_PROTECTION_CONFIDENTIAL) {
        fail_locked(s, PS_ERR_PROTO);
        return -1;
    }
    struct gen_mat *g = gen_lookup(sf, sf->send_gen);
    if (!g) {
        fail_locked(s, PS_ERR_CRYPTO);
        return -1;
    }
    struct spt_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = SPT_VERSION;
    hdr.type = type;
    hdr.protection = protection;
    hdr.flags = flags;
    hdr.subflow_id = sf->id;
    hdr.key_generation = sf->send_gen;
    hdr.record_sequence = sf->send_seq;
    hdr.logical_offset = logical;
    hdr.plaintext_length = plain_len;
    size_t wire = spt_frame_wire_len(plain_len);
    uint8_t *frame = frame_get_locked(s, wire);
    struct wire_slot *slot = (struct wire_slot *)calloc(1, sizeof(*slot));
    struct crypto_job *job = (struct crypto_job *)calloc(1, sizeof(*job));
    if (!frame || !slot || !job) {
        frame_put_locked(s, frame, wire);
        free(slot);
        free(job);
        fail_locked(s, PS_ERR_NOMEM);
        return -1;
    }
    spt_header_encode(frame, &hdr);
    slot->seq = sf->send_seq;
    slot->frame = frame;
    slot->len = wire;
    slot->next = NULL;
    if (sf->out_tail)
        sf->out_tail->next = slot;
    else
        sf->out_head = slot;
    sf->out_tail = slot;
    sf->out_bytes += wire;
    job->op_open = 0;
    job->mac = protection == SPT_PROTECTION_AUTHENTICATED;
    job->alg = s->aead;
    if (job->mac) {
        memcpy(job->key, g->send_mac, SPT_KEY_LEN);
        memcpy(job->iv, g->send_iv, SPT_IV_LEN);
    } else {
        memcpy(job->key, g->send_key, SPT_KEY_LEN);
        memcpy(job->iv, g->send_iv, SPT_IV_LEN);
    }
    job->seq = sf->send_seq;
    memcpy(job->aad, frame, SPT_FRAME_HEADER_LEN);
    if (plain_len) {
        if (batch_head)
            job->copy_src = plain;
        else
            memcpy(frame + SPT_FRAME_HEADER_LEN, plain, plain_len);
        job->in = frame + SPT_FRAME_HEADER_LEN;
        job->keep_in = 1;
    }
    job->in_len = plain_len;
    job->out = frame + SPT_FRAME_HEADER_LEN;
    job->tag = frame + SPT_FRAME_HEADER_LEN + plain_len;
    job->wslot = slot;
    job->sf = sf;
    job->aead_slot = -1;
    job->aead_ctx = sf_take_aead(sf, 0, &job->aead_slot, &job->aead_owned);
    if (!job->aead_ctx) {
        free_job(job);
        fail_locked(s, PS_ERR_NOMEM);
        return -1;
    }
    sf->send_seq++;
    if (batch_head) {
        s->jobs_inflight++;
        job->next = NULL;
        if (*batch_tail)
            (*batch_tail)->next = job;
        else
            *batch_head = job;
        *batch_tail = job;
        (*batch_count)++;
    } else {
        submit_job_locked(s, job);
    }
    return 0;
}

static int enqueue_record_locked(struct ps_session *s, struct subflow *sf,
                                 uint8_t type, uint16_t flags, uint64_t logical,
                                 const uint8_t *plain, uint32_t plain_len,
                                 uint8_t protection)
{
    return enqueue_record_batch_locked(s, sf, type, flags, logical, plain, plain_len,
                                       protection, NULL, NULL, NULL);
}

static void mark_active_locked(struct ps_session *s, struct subflow *sf)
{
    if (sf->state == SF_ACTIVE)
        return;
    sf->state = SF_ACTIVE;
    if (!sf->counted_active) {
        sf->counted_active = 1;
        s->n_active++;
    }
    sf->want_read = 1;
    if (sf->fd >= 0)
        queue_io(s, sf->fd, 1, sf->want_write);
    if (s->state == PS_STATE_NEGOTIATING && s->expect > 0 && s->n_active >= s->expect) {
        s->state = PS_STATE_OPEN;
        ps_scale_state_init(&s->scale, s->n_active);
        s->scale_inited = 1;
        s->last_scale_ms = ps_now_ms();
        s->byte_mark = s->app_tx + s->app_rx;
        pthread_cond_broadcast(&s->cv);
        struct action a;
        memset(&a, 0, sizeof(a));
        a.type = ACT_WRITABLE;
        queue_act(s, &a);
        ps_log("session open on %u subflows", s->n_active);
    }
    if (s->eos_pending)
        send_eos_locked(s);
}

static void try_end_locked(struct ps_session *s, struct subflow *sf)
{
    if (!sf->drain || sf->end_sent || sf->state == SF_RETIRED)
        return;
    if (sf->out_head || sf->preface_off < sf->preface_len)
        return;
    if (enqueue_record_locked(s, sf, SPT_REC_SUBFLOW_END, 0, 0, NULL, 0,
                              SPT_PROTECTION_CONFIDENTIAL) != 0)
        return;
    sf->end_sent = 1;
}

static void retire_locked(struct ps_session *s, struct subflow *sf)
{
    if (sf->state == SF_RETIRED)
        return;
    if (!(sf->end_sent && sf->end_recv))
        return;
    sf->state = SF_RETIRED;
    if (sf->counted_active) {
        sf->counted_active = 0;
        if (s->n_active)
            s->n_active--;
    }
    uint8_t body[4];
    ps_put_u32(body, sf->id);
    queue_ctrl_locked(s, SPT_CTRL_SUBFLOW_RETIRED, body, sizeof(body));
    if (sf->fd >= 0) {
        sf->close_pending = 1;
        struct action a;
        memset(&a, 0, sizeof(a));
        a.type = ACT_STOP;
        a.fd = sf->fd;
        queue_act(s, &a);
        queue_poke(s);
    }
    pthread_cond_broadcast(&s->cv);
}

static int logical_ok(struct ps_session *s, uint64_t off, uint32_t len)
{
    if ((uint64_t)len > UINT64_MAX - off)
        return 0;
    if (s->got_eos && off + len > s->eos_off)
        return 0;
    return 1;
}

static void note_data_locked(struct ps_session *s)
{
    pthread_cond_broadcast(&s->cv);
    if (!s->in_user_read) {
        struct action a;
        memset(&a, 0, sizeof(a));
        a.type = ACT_READABLE;
        queue_act(s, &a);
    }
}

static void maybe_window_locked(struct ps_session *s)
{
    uint64_t want = s->reassembly.deliver + (uint64_t)s->recv_window;
    if (want <= s->advertised)
        return;
    uint64_t credit = s->advertised - s->reassembly.deliver;
    uint64_t delta = want - s->advertised;
    uint64_t step = s->recv_window / 4;
    if (step > 16ull * 1024 * 1024)
        step = 16ull * 1024 * 1024;
    if (step < s->frame_size)
        step = s->frame_size;
    if (delta < step && credit > s->recv_window / 2)
        return;
    uint8_t body[8];
    ps_put_u64(body, want);
    if (queue_ctrl_locked(s, SPT_CTRL_WINDOW_UPDATE, body, sizeof(body)) == 0)
        s->advertised = want;
}

static void apply_slot_locked(struct ps_session *s, struct subflow *sf, struct plain_slot *slot)
{
    if (!slot->ok) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    const struct spt_header *h = &slot->hdr;
    if (h->flags & ~SPT_FF_FIN) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (h->type != SPT_REC_DATA && h->protection != SPT_PROTECTION_CONFIDENTIAL) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (!spt_protection_accepts(s->min_protection, h->protection)) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (sf->recv_gen == 0 && h->record_sequence == 0 && h->key_generation == 0) {
        uint8_t expect = s->is_server ? SPT_REC_JOIN : SPT_REC_JOIN_ACK;
        if (h->type != expect || h->plaintext_length != SPT_JOIN_PLAIN_LEN) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        struct spt_join_plain join;
        if (spt_join_decode(slot->plain, &join) != 0) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        uint8_t role = s->is_server ? SPT_ROLE_CLIENT : SPT_ROLE_SERVER;
        if (join.role != role || join.subflow_id != sf->id || join.key_generation != 0 ||
            memcmp(join.session_id, s->session_id, SPT_SESSION_ID_LEN) != 0 ||
            memcmp(join.client_nonce, sf->client_nonce, SPT_NONCE_LEN) != 0 ||
            memcmp(join.server_nonce, sf->server_nonce, SPT_NONCE_LEN) != 0 ||
            memcmp(join.hello_hash, s->hello_hash, SPT_HASH_LEN) != 0) {
            fail_locked(s, PS_ERR_AUTH);
            return;
        }
        if (s->is_server) {
            struct spt_join_plain ack = join;
            uint8_t raw[SPT_JOIN_PLAIN_LEN];
            ack.role = SPT_ROLE_SERVER;
            if (spt_join_encode(raw, &ack) != 0) {
                fail_locked(s, PS_ERR_PROTO);
                return;
            }
            if (enqueue_record_locked(s, sf, SPT_REC_JOIN_ACK, 0, 0, raw, SPT_JOIN_PLAIN_LEN,
                                      SPT_PROTECTION_CONFIDENTIAL) != 0)
                return;
            mark_active_locked(s, sf);
            return;
        }
        mark_active_locked(s, sf);
        return;
    }
    if (h->type == SPT_REC_DATA) {
        if (h->plaintext_length == 0 || (h->flags & SPT_FF_FIN) || sf->state != SF_ACTIVE) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        if (!logical_ok(s, h->logical_offset, h->plaintext_length)) {
            fail_locked(s, PS_ERR_FLOW);
            return;
        }
        uint8_t *plain = slot->plain;
        size_t cap = slot->plain_cap;
        slot->plain = NULL;
        slot->plain_cap = 0;
        int ir = spt_reassembly_adopt_pooled(&s->reassembly, h->logical_offset,
                                             plain, h->plaintext_length, cap);
        if (ir == -2) {
            fail_locked(s, PS_ERR_FLOW);
            return;
        }
        if (ir == -3) {
            fail_locked(s, PS_ERR_NOMEM);
            return;
        }
        if (ir != 0) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        s->records_rx++;
        return;
    }
    if (h->type == SPT_REC_EOS) {
        if (h->plaintext_length != 0 || !(h->flags & SPT_FF_FIN)) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        if (s->got_eos && s->eos_off != h->logical_offset) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        s->got_eos = 1;
        s->eos_off = h->logical_offset;
        if (s->reassembly.deliver > s->eos_off) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        note_data_locked(s);
        return;
    }
    if (h->type == SPT_REC_SUBFLOW_END) {
        if (h->plaintext_length != 0) {
            fail_locked(s, PS_ERR_PROTO);
            return;
        }
        sf->end_recv = 1;
        sf->drain = 1;
        try_end_locked(s, sf);
        retire_locked(s, sf);
        return;
    }
    fail_locked(s, PS_ERR_PROTO);
}

static void apply_sf_locked(struct ps_session *s, struct subflow *sf)
{
    if (!sf || s->state == PS_STATE_FAILED)
        return;
    int applied = 0;
    while (sf->in_head && sf->in_head->ready) {
        struct plain_slot *slot = sf->in_head;
        sf->in_head = slot->next;
        if (!sf->in_head)
            sf->in_tail = NULL;
        apply_slot_locked(s, sf, slot);
        spt_reassembly_put_buf(&s->reassembly, slot->plain, slot->plain_cap);
        free(slot);
        applied = 1;
        if (s->state == PS_STATE_FAILED)
            return;
    }
    if (applied && s->reassembly.head && s->reassembly.head->off == s->reassembly.deliver)
        note_data_locked(s);
}

static void apply_all_locked(struct ps_session *s)
{
    if (s->state == PS_STATE_FAILED)
        return;
    for (uint32_t i = 0; i < s->sf_count; i++) {
        apply_sf_locked(s, &s->sf[i]);
        if (s->state == PS_STATE_FAILED)
            return;
    }
}

static uint8_t *rx_ptr(const struct subflow *sf)
{
    return sf->rx + sf->rx_off;
}

static size_t rx_live(const struct subflow *sf)
{
    return sf->rx_len - sf->rx_off;
}

static void rx_compact(struct subflow *sf)
{
    if (sf->rx_off == 0)
        return;
    size_t live = rx_live(sf);
    if (live)
        memmove(sf->rx, sf->rx + sf->rx_off, live);
    sf->rx_len = live;
    sf->rx_off = 0;
}

static int frame_ready(const struct subflow *sf)
{
    if (!sf->rx || rx_live(sf) < SPT_FRAME_HEADER_LEN)
        return 0;
    struct spt_header hdr;
    if (spt_header_decode(rx_ptr(sf), &hdr) != 0)
        return 1;
    return rx_live(sf) >= spt_frame_wire_len(hdr.plaintext_length);
}

static void parse_rx_locked(struct ps_session *s, struct subflow *sf, unsigned *budget)
{
    struct crypto_job *batch_head = NULL;
    struct crypto_job *batch_tail = NULL;
    unsigned batch_count = 0;
    while (*budget > 0 && s->state != PS_STATE_FAILED && !sf->read_paused) {
        if (sf->in_flight >= RX_PIPELINE) {
            sf->read_paused = 1;
            sf->want_read = 0;
            if (sf->fd >= 0)
                queue_io(s, sf->fd, 0, sf->want_write);
            break;
        }
        if (rx_live(sf) < SPT_FRAME_HEADER_LEN)
            break;
        struct spt_header hdr;
        if (spt_header_decode(rx_ptr(sf), &hdr) != 0) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        if (hdr.subflow_id != sf->id || hdr.plaintext_length > s->frame_size) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        size_t need = spt_frame_wire_len(hdr.plaintext_length);
        if (rx_live(sf) < need)
            break;
        struct gen_mat *g = NULL;
        if (hdr.key_generation == sf->recv_gen) {
            if (hdr.record_sequence != sf->parse_seq) {
                fail_locked(s, PS_ERR_PROTO);
                break;
            }
            g = gen_lookup(sf, hdr.key_generation);
        } else if (hdr.key_generation == sf->recv_gen + 1 && hdr.record_sequence == 0) {
            g = gen_lookup(sf, hdr.key_generation);
            if (!g) {
                fail_locked(s, PS_ERR_CRYPTO);
                break;
            }
            sf->recv_gen = hdr.key_generation;
            sf->parse_seq = 0;
        } else {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        if (!g) {
            fail_locked(s, PS_ERR_CRYPTO);
            break;
        }
        struct plain_slot *slot = (struct plain_slot *)calloc(1, sizeof(*slot));
        struct crypto_job *job = (struct crypto_job *)calloc(1, sizeof(*job));
        size_t payload_cap = 0;
        uint8_t *payload = spt_reassembly_get_buf(&s->reassembly,
                                                  hdr.plaintext_length ? hdr.plaintext_length : 1,
                                                  &payload_cap);
        if (!slot || !job || !payload) {
            free(slot);
            free(job);
            spt_reassembly_put_buf(&s->reassembly, payload, payload_cap);
            fail_locked(s, PS_ERR_NOMEM);
            break;
        }
        job->copy_src = hdr.plaintext_length ? (rx_ptr(sf) + SPT_FRAME_HEADER_LEN) : NULL;
        memcpy(job->tag_store, rx_ptr(sf) + SPT_FRAME_HEADER_LEN + hdr.plaintext_length, SPT_TAG_LEN);
        sf->rx_off += need;
        sf->parse_seq++;
        slot->hdr = hdr;
        slot->plain = payload;
        slot->plain_cap = payload_cap;
        slot->next = NULL;
        if (sf->in_tail)
            sf->in_tail->next = slot;
        else
            sf->in_head = slot;
        sf->in_tail = slot;
        sf->in_flight++;
        job->op_open = 1;
        job->mac = hdr.protection == SPT_PROTECTION_AUTHENTICATED;
        job->alg = s->aead;
        if (job->mac) {
            memcpy(job->key, g->recv_mac, SPT_KEY_LEN);
            memcpy(job->iv, g->recv_iv, SPT_IV_LEN);
        } else {
            memcpy(job->key, g->recv_key, SPT_KEY_LEN);
            memcpy(job->iv, g->recv_iv, SPT_IV_LEN);
        }
        job->seq = hdr.record_sequence;
        spt_header_encode(job->aad, &hdr);
        job->in = hdr.plaintext_length ? payload : NULL;
        job->in_len = hdr.plaintext_length;
        job->out = hdr.plaintext_length ? payload : NULL;
        job->keep_in = 1;
        job->tag = job->tag_store;
        job->pslot = slot;
        job->sf = sf;
        job->aead_slot = -1;
        job->aead_ctx = sf_take_aead(sf, 1, &job->aead_slot, &job->aead_owned);
        if (!job->aead_ctx) {
            free_job(job);
            fail_locked(s, PS_ERR_NOMEM);
            break;
        }
        s->jobs_inflight++;
        job->next = NULL;
        if (batch_tail)
            batch_tail->next = job;
        else
            batch_head = job;
        batch_tail = job;
        batch_count++;
        (*budget)--;
    }
    if (batch_head) {
        unlock_s(s);
        for (struct crypto_job *j = batch_head; j; j = j->next) {
            if (j->copy_src && j->in_len) {
                memcpy(j->in, j->copy_src, j->in_len);
                j->copy_src = NULL;
            }
        }
        if (sf->rx_off == sf->rx_len) {
            sf->rx_off = 0;
            sf->rx_len = 0;
        } else if (sf->rx_off > sf->rx_cap / 2) {
            rx_compact(sf);
        }
        lock_s(s);
        submit_batch_locked(s, batch_head, batch_tail, batch_count);
    }
}

static void send_eos_locked(struct ps_session *s)
{
    if (s->send_fin)
        return;
    struct subflow *sf = NULL;
    for (uint32_t n = 0; n < s->sf_count; n++) {
        struct subflow *c = &s->sf[(s->rr + n) % s->sf_count];
        if (c->used && c->state == SF_ACTIVE && c->keys_ready) {
            sf = c;
            break;
        }
    }
    if (!sf) {
        s->eos_pending = 1;
        return;
    }
    if (enqueue_record_locked(s, sf, SPT_REC_EOS, SPT_FF_FIN, s->send_off, NULL, 0,
                              SPT_PROTECTION_CONFIDENTIAL) != 0)
        return;
    s->send_fin = 1;
    s->eos_pending = 0;
    uint8_t body[4];
    ps_put_u32(body, SPT_E_OK);
    queue_ctrl_locked(s, SPT_CTRL_CLOSE, body, sizeof(body));
}

static void maybe_switch_gen_locked(struct ps_session *s, struct subflow *sf)
{
    (void)s;
    if (!sf->local_announced || !sf->remote_rekey)
        return;
    if (sf->rekey_target != sf->send_gen + 1)
        return;
    sf->send_gen = sf->rekey_target;
    sf->send_seq = 0;
    sf->local_announced = 0;
    sf->remote_rekey = 0;
    sf->rekey_wait = 0;
    pthread_cond_broadcast(&s->cv);
    ps_log("subflow %u rekeyed to generation %u", sf->id, sf->send_gen);
}

static void on_rekey_locked(struct ps_session *s, uint32_t id, uint32_t gen, int is_ack)
{
    struct subflow *sf = sf_by_id(s, id);
    if (!sf || gen != sf->send_gen + 1) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (!alloc_gen(s, sf, gen)) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    sf->rekey_target = gen;
    sf->remote_rekey = 1;
    if (!is_ack && !sf->local_announced) {
        uint8_t body[8];
        ps_put_u32(body, id);
        ps_put_u32(body + 4, gen);
        if (queue_ctrl_locked(s, SPT_CTRL_KEY_UPDATE_ACK, body, sizeof(body)) != 0)
            return;
        sf->local_announced = 1;
    }
    if (sf->rekey_wait)
        sf->local_announced = 1;
    maybe_switch_gen_locked(s, sf);
}

static int start_rekey_locked(struct ps_session *s, struct subflow *sf)
{
    if (!sf->keys_ready || sf->state != SF_ACTIVE)
        return -1;
    if (sf->rekey_wait || sf->local_announced)
        return 0;
    if (sf->send_gen != sf->recv_gen)
        return -1;
    uint32_t gen = sf->send_gen + 1;
    if (!alloc_gen(s, sf, gen))
        return -1;
    uint8_t body[8];
    ps_put_u32(body, sf->id);
    ps_put_u32(body + 4, gen);
    if (queue_ctrl_locked(s, SPT_CTRL_KEY_UPDATE, body, sizeof(body)) != 0)
        return -1;
    sf->rekey_target = gen;
    sf->rekey_wait = 1;
    sf->local_announced = 1;
    return 0;
}

static void open_one_locked(struct ps_session *s)
{
    if (s->is_server || s->sf_count >= PS_MAX_SUBFLOWS || s->sf_count >= s->max_sockets)
        return;
    uint32_t id = s->sf_count;
    struct subflow *sf = &s->sf[id];
    memset(sf, 0, sizeof(*sf));
    sf->fd = -1;
    sf->used = 1;
    sf->id = id;
    sf->state = SF_OPEN_SENT;
    if (RAND_bytes(sf->client_nonce, SPT_NONCE_LEN) != 1) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    s->sf_count = id + 1;
    struct spt_subflow_hello msg;
    memset(&msg, 0, sizeof(msg));
    msg.subflow_id = id;
    memcpy(msg.nonce, sf->client_nonce, SPT_NONCE_LEN);
    uint8_t body[SPT_SUBFLOW_HELLO_LEN];
    spt_subflow_hello_encode(body, &msg);
    queue_ctrl_locked(s, SPT_CTRL_SUBFLOW_OPEN, body, sizeof(body));
    if (sf_alloc_rx(s, sf) != 0)
        fail_locked(s, PS_ERR_NOMEM);
}

static unsigned live_count(const struct ps_session *s)
{
    unsigned n = 0;
    for (uint32_t i = 0; i < s->sf_count; i++) {
        if (s->sf[i].used && s->sf[i].state != SF_RETIRED && s->sf[i].state != SF_UNUSED)
            n++;
    }
    return n;
}

static void apply_socket_target_locked(struct ps_session *s, unsigned target)
{
    if (s->is_server || s->state != PS_STATE_OPEN)
        return;
    if (target < s->min_sockets)
        target = s->min_sockets;
    if (target > s->max_sockets)
        target = s->max_sockets;
    unsigned live = live_count(s);
    while (live < target && s->sf_count < s->max_sockets && s->sf_count < PS_MAX_SUBFLOWS) {
        unsigned before = s->sf_count;
        open_one_locked(s);
        if (s->state == PS_STATE_FAILED || s->sf_count == before)
            break;
        live++;
    }
    unsigned active = 0;
    for (uint32_t i = 0; i < s->sf_count; i++) {
        if (s->sf[i].state == SF_ACTIVE && !s->sf[i].drain)
            active++;
    }
    for (int id = (int)s->sf_count - 1; id >= 0 && active > target; id--) {
        struct subflow *sf = &s->sf[id];
        if (sf->state != SF_ACTIVE || sf->drain)
            continue;
        sf->drain = 1;
        sf->state = SF_DRAINING;
        uint8_t body[4];
        ps_put_u32(body, sf->id);
        queue_ctrl_locked(s, SPT_CTRL_SUBFLOW_DRAIN, body, sizeof(body));
        try_end_locked(s, sf);
        active--;
    }
}

static void hash_hellos(struct ps_session *s)
{
    uint8_t cat[SPT_CLIENT_HELLO_LEN + SPT_SERVER_HELLO_LEN];
    memcpy(cat, s->client_hello, SPT_CLIENT_HELLO_LEN);
    memcpy(cat + SPT_CLIENT_HELLO_LEN, s->server_hello, SPT_SERVER_HELLO_LEN);
    spt_sha256(cat, sizeof(cat), s->hello_hash);
}

static void become_negotiated_export(struct ps_session *s)
{
    hash_hellos(s);
    s->need_export = 1;
}

static void handle_client_hello_locked(struct ps_session *s, const uint8_t *body, size_t len)
{
    if (!s->is_server || s->have_client_hello || len != SPT_CLIENT_HELLO_LEN) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    struct spt_client_hello ch;
    if (spt_client_hello_decode(body, &ch) != 0) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (ch.aead != SPT_AEAD_AES_256_GCM && ch.aead != SPT_AEAD_CHACHA20_POLY1305 &&
        ch.aead != SPT_AEAD_AES_128_GCM) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (s->aead && ch.aead != s->aead) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    unsigned cap = ch.max_sockets;
    if (cap > s->max_sockets)
        cap = s->max_sockets;
    if (cap < 1 || ch.initial_sockets < 1 || ch.frame_size < 1024 ||
        ch.recv_window < ch.frame_size) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    unsigned want = ch.initial_sockets;
    if (want > cap)
        want = cap;
    if (s->scale_mode == PS_SCALE_FIXED && s->initial_sockets > 0 && want > s->initial_sockets)
        want = s->initial_sockets;
    uint32_t frame = ch.frame_size;
    if (frame > s->frame_size)
        frame = (uint32_t)s->frame_size;
    if (frame > SPT_MAX_PLAIN || s->data_port == 0) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    s->aead = ch.aead;
    s->frame_size = frame;
    s->sf_hi = (size_t)frame * 16;
    spt_reassembly_set_buf_size(&s->reassembly, s->frame_size);
    s->max_sockets = cap;
    s->expect = want;
    s->send_limit = ch.recv_window;
    memcpy(s->client_hello, body, SPT_CLIENT_HELLO_LEN);
    memcpy(s->client_random, ch.client_random, SPT_RANDOM_LEN);
    s->have_client_hello = 1;
    if (RAND_bytes(s->server_random, SPT_RANDOM_LEN) != 1 ||
        RAND_bytes(s->session_id, SPT_SESSION_ID_LEN) != 1) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    struct spt_server_hello sh;
    memset(&sh, 0, sizeof(sh));
    sh.aead = s->aead;
    sh.initial_sockets = want;
    sh.max_sockets = s->max_sockets;
    sh.frame_size = (uint32_t)s->frame_size;
    sh.recv_window = s->recv_window;
    sh.data_port = s->data_port;
    memcpy(sh.server_random, s->server_random, SPT_RANDOM_LEN);
    memcpy(sh.session_id, s->session_id, SPT_SESSION_ID_LEN);
    if (spt_server_hello_encode(s->server_hello, &sh) != 0) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    s->have_server_hello = 1;
    s->advertised = s->recv_window;
    become_negotiated_export(s);
    queue_ctrl_locked(s, SPT_CTRL_SERVER_HELLO, s->server_hello, SPT_SERVER_HELLO_LEN);
    send_protection_locked(s);
    ps_log("server hello queued port=%u sockets=%u", s->data_port, want);
    if (!s->registered) {
        s->registered = 1;
        struct action a;
        memset(&a, 0, sizeof(a));
        a.type = ACT_REGISTER;
        memcpy(a.sid, s->session_id, SPT_SESSION_ID_LEN);
        queue_act(s, &a);
    }
}

static void handle_server_hello_locked(struct ps_session *s, const uint8_t *body, size_t len)
{
    if (s->is_server || s->have_server_hello || len != SPT_SERVER_HELLO_LEN) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    struct spt_server_hello sh;
    if (spt_server_hello_decode(body, &sh) != 0) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (sh.aead != s->aead || sh.initial_sockets < 1 || sh.initial_sockets > s->max_sockets ||
        sh.frame_size < 1024 || sh.frame_size > s->frame_size || sh.data_port == 0 ||
        sh.recv_window < sh.frame_size) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    memcpy(s->server_hello, body, SPT_SERVER_HELLO_LEN);
    memcpy(s->server_random, sh.server_random, SPT_RANDOM_LEN);
    memcpy(s->session_id, sh.session_id, SPT_SESSION_ID_LEN);
    s->have_server_hello = 1;
    s->frame_size = sh.frame_size;
    s->sf_hi = s->frame_size * 16;
    spt_reassembly_set_buf_size(&s->reassembly, s->frame_size);
    s->max_sockets = sh.max_sockets < s->max_sockets ? sh.max_sockets : s->max_sockets;
    if (s->min_sockets > s->max_sockets)
        s->min_sockets = s->max_sockets;
    s->expect = sh.initial_sockets;
    s->send_limit = sh.recv_window;
    s->data_port = sh.data_port;
    s->advertised = s->recv_window;
    if (s->peer_len)
        ps_addr_set_port((struct sockaddr *)&s->peer, s->peer_len, sh.data_port);
    become_negotiated_export(s);
    for (unsigned i = 0; i < s->expect; i++)
        open_one_locked(s);
}

static void handle_subflow_open_locked(struct ps_session *s, const uint8_t *body, size_t len)
{
    if (!s->is_server || len != SPT_SUBFLOW_HELLO_LEN) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    struct spt_subflow_hello msg;
    if (spt_subflow_hello_decode(body, &msg) != 0 || msg.key_generation != 0 ||
        msg.subflow_id >= PS_MAX_SUBFLOWS) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (msg.subflow_id < s->sf_count && s->sf[msg.subflow_id].used) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    if (live_count(s) >= s->max_sockets) {
        uint8_t rej[8];
        ps_put_u32(rej, msg.subflow_id);
        ps_put_u32(rej + 4, SPT_E_PROTO);
        queue_ctrl_locked(s, SPT_CTRL_SUBFLOW_REJECT, rej, sizeof(rej));
        return;
    }
    if (msg.subflow_id >= s->sf_count)
        s->sf_count = msg.subflow_id + 1;
    struct subflow *sf = &s->sf[msg.subflow_id];
    memset(sf, 0, sizeof(*sf));
    sf->fd = -1;
    sf->used = 1;
    sf->id = msg.subflow_id;
    sf->state = SF_WAIT_TCP;
    memcpy(sf->client_nonce, msg.nonce, SPT_NONCE_LEN);
    if (RAND_bytes(sf->server_nonce, SPT_NONCE_LEN) != 1) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    sf->server_nonce_set = 1;
    if (s->root_valid && ensure_keys_locked(s, sf) != 0) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    if (sf_alloc_rx(s, sf) != 0) {
        fail_locked(s, PS_ERR_NOMEM);
        return;
    }
    struct spt_subflow_hello ack;
    memset(&ack, 0, sizeof(ack));
    ack.subflow_id = sf->id;
    memcpy(ack.nonce, sf->server_nonce, SPT_NONCE_LEN);
    uint8_t raw[SPT_SUBFLOW_HELLO_LEN];
    spt_subflow_hello_encode(raw, &ack);
    queue_ctrl_locked(s, SPT_CTRL_SUBFLOW_ACCEPT, raw, sizeof(raw));
}

static void handle_subflow_accept_locked(struct ps_session *s, const uint8_t *body, size_t len)
{
    if (s->is_server || len != SPT_SUBFLOW_HELLO_LEN) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    struct spt_subflow_hello msg;
    if (spt_subflow_hello_decode(body, &msg) != 0) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    struct subflow *sf = sf_by_id(s, msg.subflow_id);
    if (!sf || sf->state != SF_OPEN_SENT || msg.key_generation != 0) {
        fail_locked(s, PS_ERR_PROTO);
        return;
    }
    memcpy(sf->server_nonce, msg.nonce, SPT_NONCE_LEN);
    sf->server_nonce_set = 1;
    if (!s->root_valid) {
        sf->state = SF_WAIT_TCP;
        sf->need_connect = 1;
        queue_poke(s);
        return;
    }
    if (ensure_keys_locked(s, sf) != 0) {
        fail_locked(s, PS_ERR_CRYPTO);
        return;
    }
    sf->state = SF_WAIT_TCP;
    sf->need_connect = 1;
    queue_poke(s);
}

static void handle_ctrl_locked(struct ps_session *s, uint16_t type, const uint8_t *body, size_t len)
{
    switch (type) {
    case SPT_CTRL_CLIENT_HELLO:
        handle_client_hello_locked(s, body, len);
        break;
    case SPT_CTRL_SERVER_HELLO:
        handle_server_hello_locked(s, body, len);
        break;
    case SPT_CTRL_SUBFLOW_OPEN:
        handle_subflow_open_locked(s, body, len);
        break;
    case SPT_CTRL_SUBFLOW_ACCEPT:
        handle_subflow_accept_locked(s, body, len);
        break;
    case SPT_CTRL_SUBFLOW_REJECT:
        fail_locked(s, PS_ERR_PROTO);
        break;
    case SPT_CTRL_WINDOW_UPDATE: {
        if (len != SPT_WINDOW_LEN) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        uint64_t lim = ps_get_u64(body);
        if (lim > s->send_limit) {
            s->send_limit = lim;
            pthread_cond_broadcast(&s->cv);
            if (s->send_stalled) {
                struct action a;
                memset(&a, 0, sizeof(a));
                a.type = ACT_WRITABLE;
                queue_act(s, &a);
            }
        }
        break;
    }
    case SPT_CTRL_SUBFLOW_DRAIN: {
        if (len != 4) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        struct subflow *sf = sf_by_id(s, ps_get_u32(body));
        if (!sf || (sf->state != SF_ACTIVE && sf->state != SF_DRAINING)) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        sf->drain = 1;
        sf->state = SF_DRAINING;
        try_end_locked(s, sf);
        break;
    }
    case SPT_CTRL_SUBFLOW_RETIRED:
        break;
    case SPT_CTRL_CLOSE:
    case SPT_CTRL_ERROR:
        if (type == SPT_CTRL_ERROR)
            fail_locked(s, PS_ERR_PROTO);
        break;
    case SPT_CTRL_SCALE_REQUEST:
        if (len != 4) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        s->peer_scale = ps_get_u32(body);
        if (!s->is_server && s->scale_mode == PS_SCALE_AUTO && !s->scale.congestion &&
            s->state == PS_STATE_OPEN && s->peer_scale >= s->min_sockets &&
            s->peer_scale <= s->max_sockets)
            apply_socket_target_locked(s, s->peer_scale);
        break;
    case SPT_CTRL_KEY_UPDATE:
    case SPT_CTRL_KEY_UPDATE_ACK:
        if (len != SPT_KEY_UPDATE_LEN) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        on_rekey_locked(s, ps_get_u32(body), ps_get_u32(body + 4),
                        type == SPT_CTRL_KEY_UPDATE_ACK);
        break;
    case SPT_CTRL_PROTECTION: {
        if (len != 4 || body[2] != 0 || body[3] != 0) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        uint8_t minp = body[0];
        uint8_t mac = body[1];
        if ((minp != SPT_PROTECTION_CONFIDENTIAL && minp != SPT_PROTECTION_AUTHENTICATED) ||
            mac != SPT_MAC_HMAC_SHA256) {
            fail_locked(s, PS_ERR_PROTO);
            break;
        }
        if (s->have_peer_protection) {
            if (s->peer_min != minp)
                fail_locked(s, PS_ERR_PROTO);
            break;
        }
        s->peer_min = minp;
        s->have_peer_protection = 1;
        pthread_cond_broadcast(&s->cv);
        break;
    }
    default:
        fail_locked(s, PS_ERR_PROTO);
        break;
    }
}

static void send_protection_locked(struct ps_session *s)
{
    if (s->protection_sent || s->state == PS_STATE_FAILED)
        return;
    uint8_t body[4];
    body[0] = s->min_protection;
    body[1] = SPT_MAC_HMAC_SHA256;
    body[2] = 0;
    body[3] = 0;
    if (queue_ctrl_locked(s, SPT_CTRL_PROTECTION, body, 4) != 0)
        return;
    s->protection_sent = 1;
}

static void client_begin(struct ps_session *s)
{
    if (s->peer_len == 0 && s->ctrl_fd >= 0) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getpeername(s->ctrl_fd, (struct sockaddr *)&ss, &sl) == 0) {
            lock_s(s);
            if (s->peer_len == 0) {
                memcpy(&s->peer, &ss, sl);
                s->peer_len = sl;
            }
            unlock_s(s);
        }
    }
    lock_s(s);
    if (s->have_client_hello || s->is_server) {
        unlock_s(s);
        return;
    }
    struct ps_hwinfo hw;
    memset(&hw, 0, sizeof(hw));
    if (s->ctrl_fd >= 0)
        ps_discover_fd(s->ctrl_fd, &hw);
    s->hw = hw;
    unsigned n = s->initial_sockets;
    if (n == 0) {
        if (s->scale_mode == PS_SCALE_FIXED)
            n = s->max_sockets;
        else
            n = ps_suggest_sockets(&hw, s->min_sockets, s->max_sockets);
    }
    if (n < s->min_sockets)
        n = s->min_sockets;
    if (n > s->max_sockets)
        n = s->max_sockets;
    if (n == 0)
        n = 1;
    s->proposed = n;
    if (RAND_bytes(s->client_random, SPT_RANDOM_LEN) != 1) {
        fail_locked(s, PS_ERR_CRYPTO);
        unlock_s(s);
        return;
    }
    struct spt_client_hello ch;
    memset(&ch, 0, sizeof(ch));
    ch.aead = s->aead;
    ch.min_sockets = s->min_sockets;
    ch.max_sockets = s->max_sockets;
    ch.initial_sockets = n;
    ch.frame_size = (uint32_t)s->frame_size;
    ch.recv_window = s->recv_window;
    ch.flags = 1;
    memcpy(ch.client_random, s->client_random, SPT_RANDOM_LEN);
    if (spt_client_hello_encode(s->client_hello, &ch) != 0) {
        fail_locked(s, PS_ERR_PROTO);
        unlock_s(s);
        return;
    }
    s->have_client_hello = 1;
    s->advertised = s->recv_window;
    queue_ctrl_locked(s, SPT_CTRL_CLIENT_HELLO, s->client_hello, SPT_CLIENT_HELLO_LEN);
    send_protection_locked(s);
    ps_log("client hello queued sockets=%u", s->proposed);
    unlock_s(s);
}

static struct subflow *pick_sf(struct ps_session *s)
{
    if (s->sf_count == 0)
        return NULL;
    size_t need = spt_frame_wire_len((uint32_t)s->frame_size);
    struct subflow *best = NULL;
    uint32_t best_idx = 0;
    for (uint32_t n = 0; n < s->sf_count; n++) {
        uint32_t i = (s->rr + n) % s->sf_count;
        struct subflow *sf = &s->sf[i];
        if (!sf->used || sf->state != SF_ACTIVE || sf->drain || !sf->keys_ready)
            continue;
        if (sf->out_bytes + need > s->sf_hi)
            continue;
        if (sf->send_seq >= SPT_REKEY_RECORD_LIMIT)
            continue;
        if (!best || sf->out_bytes < best->out_bytes) {
            best = sf;
            best_idx = i;
            if (sf->out_bytes == 0)
                break;
        }
    }
    if (best)
        s->rr = (best_idx + 1) % s->sf_count;
    return best;
}

static size_t submit_locked(struct ps_session *s, const uint8_t *buf, size_t len,
                            uint8_t protection, int *err)
{
    size_t acc = 0;
    *err = PS_OK;
    struct crypto_job *batch_head = NULL;
    struct crypto_job *batch_tail = NULL;
    unsigned batch_count = 0;
    while (acc < len) {
        if (s->state == PS_STATE_FAILED) {
            *err = s->err ? s->err : PS_ERR_PROTO;
            break;
        }
        if (s->send_fin || s->closing) {
            *err = PS_ERR_CLOSED;
            break;
        }
        if (s->state != PS_STATE_OPEN) {
            *err = PS_ERR_AGAIN;
            s->send_stalled = 1;
            break;
        }
        if (s->send_off >= s->send_limit) {
            *err = PS_ERR_AGAIN;
            s->send_stalled = 1;
            break;
        }
        struct subflow *sf = pick_sf(s);
        if (!sf) {
            *err = PS_ERR_AGAIN;
            s->send_stalled = 1;
            break;
        }
        uint64_t credit = s->send_limit - s->send_off;
        size_t chunk = len - acc;
        if (chunk > s->frame_size)
            chunk = s->frame_size;
        if ((uint64_t)chunk > credit)
            chunk = (size_t)credit;
        if (chunk == 0) {
            *err = PS_ERR_AGAIN;
            break;
        }
        if (protection == SPT_PROTECTION_AUTHENTICATED) {
            if (s->min_protection != SPT_PROTECTION_AUTHENTICATED) {
                *err = PS_ERR_AUTH;
                break;
            }
            if (!s->have_peer_protection) {
                *err = PS_ERR_AGAIN;
                s->send_stalled = 1;
                break;
            }
            if (s->peer_min != SPT_PROTECTION_AUTHENTICATED) {
                *err = PS_ERR_AUTH;
                break;
            }
        } else if (protection != SPT_PROTECTION_CONFIDENTIAL) {
            *err = PS_ERR_INVAL;
            break;
        }
        if (enqueue_record_batch_locked(s, sf, SPT_REC_DATA, 0, s->send_off, buf + acc,
                                        (uint32_t)chunk, protection,
                                        &batch_head, &batch_tail, &batch_count) != 0) {
            *err = s->err ? s->err : PS_ERR_NOMEM;
            break;
        }
        s->send_off += chunk;
        s->app_tx += chunk;
        acc += chunk;
        s->send_stalled = 0;
    }
    if (batch_head) {
        s->send_hold++;
        unlock_s(s);
        for (struct crypto_job *j = batch_head; j; j = j->next) {
            if (j->copy_src && j->in_len) {
                memcpy(j->in, j->copy_src, j->in_len);
                j->copy_src = NULL;
            }
        }
        lock_s(s);
        if (s->send_hold)
            s->send_hold--;
        if (s->closing || s->state == PS_STATE_CLOSED)
            pthread_cond_broadcast(&s->cv);
        submit_batch_locked(s, batch_head, batch_tail, batch_count);
    }
    return acc;
}

static int eof_locked(const struct ps_session *s)
{
    return s->got_eos && spt_reassembly_available(&s->reassembly) == 0 &&
           s->reassembly.deliver == s->eos_off;
}

static void run_ready_work(struct ps_session *s, int limit)
{
    if (s->nworkers > 0 && !s->workers_stopped)
        return;
    int ran = 0;
    for (int guard = 0; guard < 100000; guard++) {
        if (limit == 0)
            break;
        lock_s(s);
        if (s->state != PS_STATE_FAILED)
            apply_all_locked(s);
        struct crypto_job *job = s->inline_head;
        if (job) {
            s->inline_head = job->next;
            if (!s->inline_head)
                s->inline_tail = NULL;
        }
        int failed = s->state == PS_STATE_FAILED;
        unlock_s(s);
        if (!job)
            break;
        ran = 1;
        if (failed) {
            lock_s(s);
            free_job(job);
            unlock_s(s);
            continue;
        }
        int ok = execute_job(job);
        lock_s(s);
        finish_job_locked(s, job, ok);
        free_job(job);
        unlock_s(s);
        if (limit > 0)
            limit--;
    }
    if (ran) {
        lock_s(s);
        if (s->state != PS_STATE_FAILED)
            apply_all_locked(s);
        unlock_s(s);
    }
}

static void dispatch(struct ps_session *s)
{
    lock_s(s);
    if (s->dispatching) {
        s->dispatch_again = 1;
        unlock_s(s);
        return;
    }
    s->dispatching = 1;
    s->dispatch_owner = pthread_self();
    for (;;) {
        struct action local[ACT_MAX];
        int n = s->nacts;
        if (n > ACT_MAX)
            n = ACT_MAX;
        memcpy(local, s->acts, (size_t)n * sizeof(local[0]));
        s->nacts = 0;
        int poke = s->poke_pending;
        s->poke_pending = 0;
        int again = s->dispatch_again;
        s->dispatch_again = 0;
        ps_io_cbs io = s->io;
        struct ps_session_hooks hooks = s->hooks;
        int skip_reg = s->unregistered;
        if (n == 0 && !poke && !again) {
            s->dispatching = 0;
            unlock_s(s);
            return;
        }
        unlock_s(s);
        for (int i = 0; i < n; i++) {
            struct action *a = &local[i];
            switch (a->type) {
            case ACT_IO:
                if (io.want_io)
                    io.want_io(io.ctx, a->fd, a->rd, a->wr);
                break;
            case ACT_STOP:
                if (io.stop_io)
                    io.stop_io(io.ctx, a->fd);
                break;
            case ACT_READABLE:
                if (io.stream_readable)
                    io.stream_readable(io.ctx);
                break;
            case ACT_WRITABLE:
                if (io.stream_writable)
                    io.stream_writable(io.ctx);
                break;
            case ACT_ERROR:
                if (io.session_error)
                    io.session_error(io.ctx, a->err);
                break;
            case ACT_REGISTER:
                if (!skip_reg && hooks.register_session)
                    hooks.register_session(hooks.ctx, a->sid, s);
                break;
            default:
                break;
            }
        }
        if (poke && io.poke)
            io.poke(io.ctx);
        lock_s(s);
    }
}

void ps_session_progress(ps_session_t *session)
{
    if (!session)
        return;
    run_ready_work(session, -1);
    dispatch(session);
}

void ps_session_progress_step(ps_session_t *session)
{
    if (!session)
        return;
    run_ready_work(session, 1);
    dispatch(session);
}

int ps_session_inline_pending(const ps_session_t *session)
{
    if (!session)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    if (s->nworkers > 0 && !s->workers_stopped)
        return 0;
    lock_s(s);
    int yes = s->inline_head != NULL;
    unlock_s(s);
    return yes;
}

static void normalize(struct ps_session *s, const struct ps_options *in)
{
    struct ps_options d;
    ps_options_init(&d);
    struct ps_options o = in ? *in : d;
    if (o.max_sockets == 0 || o.max_sockets > PS_MAX_SUBFLOWS)
        o.max_sockets = o.max_sockets == 0 ? d.max_sockets : PS_MAX_SUBFLOWS;
    if (o.max_sockets > PS_MAX_SUBFLOWS)
        o.max_sockets = PS_MAX_SUBFLOWS;
    if (o.min_sockets == 0)
        o.min_sockets = 1;
    if (o.min_sockets > o.max_sockets)
        o.min_sockets = o.max_sockets;
    if (o.frame_size == 0)
        o.frame_size = d.frame_size;
    if (o.frame_size < 1024)
        o.frame_size = 1024;
    if (o.frame_size > SPT_MAX_PLAIN)
        o.frame_size = SPT_MAX_PLAIN;
    if (o.receive_window == 0)
        o.receive_window = d.receive_window;
    if (o.receive_window < o.frame_size)
        o.receive_window = o.frame_size;
    if (o.aead == 0)
        o.aead = PS_AEAD_AES_256_GCM;
    if (o.min_protection != PS_PROTECTION_AUTHENTICATED)
        o.min_protection = PS_PROTECTION_CONFIDENTIAL;
    if (o.scale_interval_ms == 0)
        o.scale_interval_ms = d.scale_interval_ms;
    if (o.min_transfer_size == 0)
        o.min_transfer_size = d.min_transfer_size;
    if (o.connect_timeout_ms == 0)
        o.connect_timeout_ms = d.connect_timeout_ms;
    if (o.io_timeout_ms == 0)
        o.io_timeout_ms = d.io_timeout_ms;
    if (o.max_poller_bytes == 0)
        o.max_poller_bytes = d.max_poller_bytes;
    if (o.max_poller_records == 0)
        o.max_poller_records = d.max_poller_records;
    if (o.worker_threads > 16)
        o.worker_threads = 16;
    s->scale_mode = o.scale_mode;
    s->min_sockets = o.min_sockets;
    s->max_sockets = o.max_sockets;
    s->initial_sockets = o.initial_sockets;
    s->nworkers = o.worker_threads;
    s->scale_interval_ms = o.scale_interval_ms;
    s->min_transfer_size = o.min_transfer_size;
    s->frame_size = o.frame_size;
    s->recv_window = o.receive_window;
    s->sf_hi = o.frame_size * 16;
    s->max_poller_bytes = o.max_poller_bytes;
    s->max_poller_records = o.max_poller_records;
    s->aead = (uint16_t)o.aead;
    s->min_protection = (uint8_t)o.min_protection;
    s->connect_timeout_ms = o.connect_timeout_ms;
    s->io_timeout_ms = o.io_timeout_ms;
    s->advertised = s->recv_window;
}

static void session_destroy(struct ps_session *s)
{
    lock_s(s);
    while (s->rx_hold || s->send_hold)
        pthread_cond_wait(&s->cv, &s->mu);
    unlock_s(s);
    ps_session_stop_workers(s);
    if (s->io.stop_io) {
        if (s->ctrl_fd >= 0)
            s->io.stop_io(s->io.ctx, s->ctrl_fd);
        for (uint32_t i = 0; i < s->sf_count; i++) {
            if (s->sf[i].fd >= 0)
                s->io.stop_io(s->io.ctx, s->sf[i].fd);
        }
    }
    if (s->ssl) {
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
    if (s->ctrl_fd >= 0) {
        close(s->ctrl_fd);
        s->ctrl_fd = -1;
    }
    for (uint32_t i = 0; i < PS_MAX_SUBFLOWS; i++) {
        struct subflow *sf = &s->sf[i];
        if (sf->fd >= 0)
            close(sf->fd);
        while (sf->out_head) {
            struct wire_slot *w = sf->out_head;
            sf->out_head = w->next;
            frame_put_locked(s, w->frame, w->len);
            free(w);
        }
        while (sf->in_head) {
            struct plain_slot *p = sf->in_head;
            sf->in_head = p->next;
            free(p->plain);
            free(p);
        }
        free(sf->rx);
        for (int g = 0; g < 2; g++)
            OPENSSL_cleanse(&sf->gens[g], sizeof(sf->gens[g]));
        OPENSSL_cleanse(sf->client_nonce, sizeof(sf->client_nonce));
        OPENSSL_cleanse(sf->server_nonce, sizeof(sf->server_nonce));
    }
    while (s->inline_head) {
        struct crypto_job *j = s->inline_head;
        s->inline_head = j->next;
        free_job(j);
    }
    pthread_mutex_lock(&s->job_mu);
    while (s->job_head) {
        struct crypto_job *j = s->job_head;
        s->job_head = j->next;
        free_job(j);
    }
    pthread_mutex_unlock(&s->job_mu);
    for (uint32_t i = 0; i < PS_MAX_SUBFLOWS; i++) {
        struct subflow *sf = &s->sf[i];
        for (int n = 0; n < SF_AEAD_SLOTS; n++) {
            spt_aead_ctx_free(sf->seal_ctx[n]);
            spt_aead_ctx_free(sf->open_ctx[n]);
            sf->seal_ctx[n] = NULL;
            sf->open_ctx[n] = NULL;
        }
    }
    spt_reassembly_free(&s->reassembly);
    buf_free(&s->cin);
    buf_free(&s->cout);
    OPENSSL_cleanse(s->root, sizeof(s->root));
    free(s->server_name);
    free(s->tids);
    if (s->ctx)
        SSL_CTX_free(s->ctx);
    while (s->frames) {
        struct frame_cache *n = s->frames;
        s->frames = n->next;
        free(n);
    }
    pthread_cond_destroy(&s->job_cv);
    pthread_mutex_destroy(&s->job_mu);
    pthread_cond_destroy(&s->cv);
    pthread_mutex_destroy(&s->mu);
    free(s);
}

ps_session_t *ps_session_create(int is_server, const struct ps_options *opt,
                                SSL_CTX *ctx, const struct ps_tls_config *tls,
                                const ps_io_cbs *cbs)
{
    if (!ctx)
        return NULL;
    struct ps_session *s = (struct ps_session *)calloc(1, sizeof(*s));
    if (!s) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    s->refs = 1;
    s->is_server = is_server ? 1 : 0;
    s->state = PS_STATE_INIT;
    s->ctrl_fd = -1;
    s->ctx = ctx;
    for (int i = 0; i < PS_MAX_SUBFLOWS; i++)
        s->sf[i].fd = -1;
    if (cbs)
        s->io = *cbs;
    if (tls && tls->server_name)
        s->server_name = dupstr(tls->server_name);
    normalize(s, opt);
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    pthread_mutex_init(&s->job_mu, NULL);
    pthread_cond_init(&s->job_cv, NULL);
    if (spt_reassembly_init(&s->reassembly, s->recv_window) != 0) {
        s->nworkers = 0;
        s->workers_stopped = 1;
        session_destroy(s);
        return NULL;
    }
    spt_reassembly_set_buf_size(&s->reassembly, s->frame_size);
    unsigned want_workers = s->nworkers;
    s->nworkers = 0;
    s->workers_stopped = 1;
    if (want_workers > 0) {
        s->tids = (pthread_t *)calloc(want_workers, sizeof(pthread_t));
        if (!s->tids) {
            session_destroy(s);
            return NULL;
        }
        s->workers_stopped = 0;
        for (unsigned i = 0; i < want_workers; i++) {
            if (pthread_create(&s->tids[i], NULL, worker_main, s) != 0) {
                session_destroy(s);
                return NULL;
            }
            s->nworkers = i + 1;
        }
    }
    return s;
}

void ps_session_set_hooks(ps_session_t *session, const struct ps_session_hooks *hooks)
{
    if (!session)
        return;
    lock_s(session);
    if (hooks)
        session->hooks = *hooks;
    else
        memset(&session->hooks, 0, sizeof(session->hooks));
    unlock_s(session);
}

void ps_session_ref(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    session->refs++;
    unlock_s(session);
}

void ps_session_unref(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    int left = --session->refs;
    unlock_s(session);
    if (left == 0)
        session_destroy(session);
}

void ps_session_stop_workers(ps_session_t *session)
{
    if (!session || session->workers_stopped)
        return;
    pthread_mutex_lock(&session->job_mu);
    session->stop_workers = 1;
    pthread_cond_broadcast(&session->job_cv);
    pthread_mutex_unlock(&session->job_mu);
    for (unsigned i = 0; i < session->nworkers; i++)
        pthread_join(session->tids[i], NULL);
    session->nworkers = 0;
    session->workers_stopped = 1;
}

void ps_session_mark_closing(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    session->closing = 1;
    if (session->state != PS_STATE_FAILED && session->state != PS_STATE_CLOSED)
        session->state = PS_STATE_CLOSING;
    pthread_cond_broadcast(&session->cv);
    unlock_s(session);
}

void ps_session_unregister_now(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    int do_it = session->registered && !session->unregistered;
    session->unregistered = 1;
    session->closing = 1;
    struct ps_session_hooks hooks = session->hooks;
    unlock_s(session);
    if (do_it && hooks.unregister_session)
        hooks.unregister_session(hooks.ctx, session);
}

int ps_session_attach_ssl(ps_session_t *session, SSL *ssl, int fd, int handshake_done)
{
    if (!session || !ssl || fd < 0)
        return -PS_ERR_INVAL;
    lock_s(session);
    session->ssl = ssl;
    session->ctrl_fd = fd;
    session->hs_done = handshake_done ? 1 : 0;
    session->state = handshake_done ? PS_STATE_NEGOTIATING : PS_STATE_HANDSHAKE;
    session->ctrl_want_read = 1;
    session->ctrl_want_write = handshake_done ? 0 : 1;
    unlock_s(session);
    return PS_OK;
}

SSL *ps_session_ssl(ps_session_t *session)
{
    return session ? session->ssl : NULL;
}

int ps_session_handshake_done(const ps_session_t *session)
{
    if (!session)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int d = s->hs_done;
    unlock_s(s);
    return d;
}

void ps_session_handshake_finished(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    int begin = 0;
    if (!session->hs_done) {
        session->hs_done = 1;
        session->state = PS_STATE_NEGOTIATING;
        session->ctrl_want_read = 1;
        begin = !session->is_server;
    } else if (!session->is_server && !session->have_client_hello) {
        begin = 1;
    }
    unlock_s(session);
    if (begin)
        client_begin(session);
}

int ps_session_is_control(const ps_session_t *session, int fd)
{
    if (!session || fd < 0)
        return 0;
    return session->ctrl_fd == fd;
}

int ps_session_is_connecting(const ps_session_t *session, int fd)
{
    if (!session)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    struct subflow *sf = sf_by_fd(s, fd);
    int yes = sf && sf->connecting;
    unlock_s(s);
    return yes;
}

void ps_session_fail(ps_session_t *session, int err)
{
    if (!session)
        return;
    lock_s(session);
    fail_locked(session, err);
    unlock_s(session);
    ps_session_progress(session);
}

int ps_session_control_plaintext(ps_session_t *session, const uint8_t *data, size_t len)
{
    if (!session || (!data && len))
        return -PS_ERR_INVAL;
    lock_s(session);
    if (buf_append(&session->cin, data, len) != 0) {
        fail_locked(session, PS_ERR_NOMEM);
        unlock_s(session);
        return -PS_ERR_NOMEM;
    }
    for (;;) {
        uint16_t type = 0;
        const uint8_t *body = NULL;
        size_t blen = 0;
        size_t consumed = 0;
        int pr = spt_ctrl_peek(session->cin.p + session->cin.off,
                               session->cin.len - session->cin.off, &type, &body, &blen,
                               &consumed);
        if (pr > 0)
            break;
        if (pr < 0) {
            fail_locked(session, PS_ERR_PROTO);
            break;
        }
        handle_ctrl_locked(session, type, body, blen);
        buf_consume(&session->cin, consumed);
        if (session->state == PS_STATE_FAILED)
            break;
    }
    int err = session->state == PS_STATE_FAILED ? session->err : PS_OK;
    unlock_s(session);
    return err ? -err : PS_OK;
}

void ps_session_control_eof(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    if (session->state == PS_STATE_OPEN && !session->got_eos)
        fail_locked(session, PS_ERR_CLOSED);
    else if (session->state != PS_STATE_FAILED)
        session->state = PS_STATE_CLOSED;
    pthread_cond_broadcast(&session->cv);
    unlock_s(session);
}

int ps_session_take_export(ps_session_t *session, uint8_t context[96])
{
    if (!session || !context)
        return 0;
    lock_s(session);
    int need = session->need_export && !session->root_valid && session->have_client_hello &&
               session->have_server_hello;
    if (need) {
        spt_exporter_context(context, session->client_random, session->server_random,
                             session->session_id);
    }
    unlock_s(session);
    return need;
}

void ps_session_install_root(ps_session_t *session, const uint8_t root[32])
{
    if (!session || !root)
        return;
    lock_s(session);
    if (!session->root_valid) {
        memcpy(session->root, root, SPT_ROOT_LEN);
        session->root_valid = 1;
        session->need_export = 0;
        for (uint32_t i = 0; i < session->sf_count; i++) {
            struct subflow *sf = &session->sf[i];
            if (sf->used && sf->server_nonce_set && ensure_keys_locked(session, sf) != 0)
                fail_locked(session, PS_ERR_CRYPTO);
        }
    }
    unlock_s(session);
}

int ps_session_copy_control(ps_session_t *session, uint8_t *dst, size_t cap, size_t *n)
{
    if (!session || !dst || !n)
        return -PS_ERR_INVAL;
    lock_s(session);
    size_t have = session->cout.len - session->cout.off;
    if (have > cap)
        have = cap;
    if (have)
        memcpy(dst, session->cout.p + session->cout.off, have);
    *n = have;
    unlock_s(session);
    return PS_OK;
}

void ps_session_consume_control(ps_session_t *session, size_t n)
{
    if (!session)
        return;
    lock_s(session);
    buf_consume(&session->cout, n);
    session->ctrl_want_write = session->cout.len > session->cout.off;
    pthread_cond_broadcast(&session->cv);
    unlock_s(session);
}

int ps_session_ctrl_pending(const ps_session_t *session)
{
    if (!session)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int yes = s->cout.len > s->cout.off;
    unlock_s(s);
    return yes;
}

void ps_session_set_ctrl_want(ps_session_t *session, int want_read, int want_write)
{
    if (!session)
        return;
    lock_s(session);
    session->ctrl_want_read = want_read ? 1 : 0;
    if (want_write)
        session->ctrl_want_write = 1;
    else if (session->cout.len == session->cout.off)
        session->ctrl_want_write = 0;
    unlock_s(session);
}

int ps_session_ingest(ps_session_t *session, int fd, int *again)
{
    if (again)
        *again = 0;
    if (!session)
        return -PS_ERR_INVAL;
    lock_s(session);
    struct subflow *sf = sf_by_fd(session, fd);
    if (!sf || sf->connecting || sf->state == SF_RETIRED) {
        unlock_s(session);
        return PS_OK;
    }
    if (!sf->rx) {
        fail_locked(session, PS_ERR_PROTO);
        int err = session->err;
        unlock_s(session);
        return -err;
    }
    session->rx_hold++;
    size_t got = 0;
    unsigned budget = session->max_poller_records ? session->max_poller_records : 1;
    while (session->state != PS_STATE_FAILED) {
        unsigned before = budget;
        parse_rx_locked(session, sf, &budget);
        if (session->state == PS_STATE_FAILED)
            break;
        if (sf->read_paused)
            break;
        if (frame_ready(sf) && budget == 0) {
            if (again)
                *again = 1;
            break;
        }
        if (frame_ready(sf) && budget == before && before == 0)
            break;
        size_t one = spt_frame_wire_len((uint32_t)session->frame_size);
        if (sf->rx_cap - sf->rx_len < one && sf->rx_off > 0)
            rx_compact(sf);
        size_t space = sf->rx_cap - sf->rx_len;
        if (space == 0) {
            if (frame_ready(sf)) {
                if (again)
                    *again = 1;
            } else {
                fail_locked(session, PS_ERR_PROTO);
            }
            break;
        }
        if (got >= session->max_poller_bytes) {
            if (again)
                *again = 1;
            break;
        }
        uint8_t *dst = sf->rx + sf->rx_len;
        unlock_s(session);
        ssize_t n = recv(fd, dst, space, 0);
        int errn = errno;
        lock_s(session);
        sf = sf_by_fd(session, fd);
        if (!sf || sf->connecting || sf->state == SF_RETIRED) {
            if (n > 0) {
                fail_locked(session, PS_ERR_IO);
            }
            break;
        }
        if (n < 0) {
            if (errn == EINTR)
                continue;
            if (errn == EAGAIN || errn == EWOULDBLOCK)
                break;
            fail_locked(session, PS_ERR_IO);
            break;
        }
        if (n == 0) {
            if (sf->end_recv || sf->state == SF_RETIRED || session->closing || session->got_eos)
                sf->close_pending = 1;
            else
                fail_locked(session, PS_ERR_IO);
            break;
        }
        sf->rx_len += (size_t)n;
        got += (size_t)n;
    }
    if (session->rx_hold)
        session->rx_hold--;
    if (session->closing || session->state == PS_STATE_CLOSED)
        pthread_cond_broadcast(&session->cv);
    int err = session->state == PS_STATE_FAILED ? session->err : PS_OK;
    unlock_s(session);
    return err ? -err : PS_OK;
}

int ps_session_flush(ps_session_t *session, int fd, size_t max_bytes)
{
    if (!session)
        return -PS_ERR_INVAL;
    size_t sent = 0;
    struct iovec iov[FLUSH_IOV];
    while (sent < max_bytes) {
        lock_s(session);
        struct subflow *sf = sf_by_fd(session, fd);
        if (!sf || sf->connecting || session->state == PS_STATE_FAILED) {
            int err = session->err;
            unlock_s(session);
            return err ? -err : PS_OK;
        }
        int niov = 0;
        int preface = 0;
        if (sf->preface_off < sf->preface_len) {
            size_t n = sf->preface_len - sf->preface_off;
            if (n > max_bytes - sent)
                n = max_bytes - sent;
            iov[0].iov_base = (void *)(sf->preface + sf->preface_off);
            iov[0].iov_len = n;
            niov = 1;
            preface = 1;
        } else {
            struct wire_slot *w = sf->out_head;
            size_t planned = 0;
            while (w && niov < FLUSH_IOV && planned < max_bytes - sent) {
                if (!w->ready)
                    break;
                if (!w->ok) {
                    fail_locked(session, PS_ERR_CRYPTO);
                    int err = session->err;
                    unlock_s(session);
                    return -err;
                }
                size_t left = w->len - w->off;
                if (left == 0) {
                    w = w->next;
                    continue;
                }
                size_t take = left;
                if (take > max_bytes - sent - planned)
                    take = max_bytes - sent - planned;
                iov[niov].iov_base = w->frame + w->off;
                iov[niov].iov_len = take;
                planned += take;
                niov++;
                w = w->next;
            }
        }
        if (niov == 0) {
            refresh_write_locked(session, sf);
            unlock_s(session);
            break;
        }
        session->send_hold++;
        unlock_s(session);
        ssize_t wr;
#if defined(MSG_NOSIGNAL)
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = (unsigned int)niov;
        wr = sendmsg(fd, &msg, MSG_NOSIGNAL);
#else
        wr = writev(fd, iov, niov);
#endif
        int errn = errno;
        lock_s(session);
        sf = sf_by_fd(session, fd);
        if (wr < 0) {
            if (session->send_hold)
                session->send_hold--;
            pthread_cond_broadcast(&session->cv);
            if (!sf || session->state == PS_STATE_FAILED) {
                int err = session->err;
                unlock_s(session);
                return err ? -err : PS_OK;
            }
            if (errn == EINTR) {
                unlock_s(session);
                continue;
            }
            if (errn == EAGAIN || errn == EWOULDBLOCK) {
                sf->want_write = 1;
                unlock_s(session);
                break;
            }
            fail_locked(session, PS_ERR_IO);
            int err = session->err;
            unlock_s(session);
            return -err;
        }
        if (!sf || sf->connecting || session->state == PS_STATE_FAILED) {
            if (session->send_hold)
                session->send_hold--;
            pthread_cond_broadcast(&session->cv);
            int err = session->err;
            unlock_s(session);
            return err ? -err : PS_OK;
        }
        size_t remain = (size_t)wr;
        int freed = 0;
        if (preface) {
            sf->preface_off += remain;
        } else {
            while (remain > 0 && sf->out_head) {
                struct wire_slot *slot = sf->out_head;
                size_t left = slot->len - slot->off;
                size_t adv = remain < left ? remain : left;
                slot->off += adv;
                remain -= adv;
                if (slot->off != slot->len)
                    break;
                sf->out_head = slot->next;
                if (!sf->out_head)
                    sf->out_tail = NULL;
                if (sf->out_bytes >= slot->len)
                    sf->out_bytes -= slot->len;
                session->records_tx++;
                frame_put_locked(session, slot->frame, slot->len);
                free(slot);
                try_end_locked(session, sf);
                freed = 1;
            }
        }
        if (freed && session->send_stalled)
            pthread_cond_broadcast(&session->cv);
        if (session->send_hold)
            session->send_hold--;
        if (session->closing || session->state == PS_STATE_CLOSED)
            pthread_cond_broadcast(&session->cv);
        refresh_write_locked(session, sf);
        sent += (size_t)wr;
        unlock_s(session);
    }
    return PS_OK;
}

int ps_session_on_connected(ps_session_t *session, int fd)
{
    if (!session)
        return -PS_ERR_INVAL;
    lock_s(session);
    struct subflow *sf = sf_by_fd(session, fd);
    if (!sf) {
        unlock_s(session);
        return -PS_ERR_PROTO;
    }
    sf->connecting = 0;
    sf->want_read = 1;
    if (!session->is_server) {
        if (ensure_keys_locked(session, sf) != 0) {
            fail_locked(session, PS_ERR_CRYPTO);
            unlock_s(session);
            return -PS_ERR_CRYPTO;
        }
        if (spt_preface_encode(sf->preface, sf->id, session->session_id) != 0) {
            fail_locked(session, PS_ERR_PROTO);
        } else {
            sf->preface_len = SPT_PREFACE_LEN;
            sf->preface_off = 0;
            sf->state = SF_JOINING;
            struct spt_join_plain join;
            memset(&join, 0, sizeof(join));
            join.role = SPT_ROLE_CLIENT;
            join.subflow_id = sf->id;
            memcpy(join.session_id, session->session_id, SPT_SESSION_ID_LEN);
            memcpy(join.client_nonce, sf->client_nonce, SPT_NONCE_LEN);
            memcpy(join.server_nonce, sf->server_nonce, SPT_NONCE_LEN);
            memcpy(join.hello_hash, session->hello_hash, SPT_HASH_LEN);
            uint8_t raw[SPT_JOIN_PLAIN_LEN];
            spt_join_encode(raw, &join);
            enqueue_record_locked(session, sf, SPT_REC_JOIN, 0, 0, raw, SPT_JOIN_PLAIN_LEN,
                                  SPT_PROTECTION_CONFIDENTIAL);
        }
    }
    refresh_write_locked(session, sf);
    queue_io(session, fd, sf->want_read, sf->want_write);
    int err = session->state == PS_STATE_FAILED ? session->err : PS_OK;
    unlock_s(session);
    return err ? -err : PS_OK;
}

int ps_session_local_pending(const ps_session_t *session)
{
    if (!session)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int yes = 0;
    if (s->state != PS_STATE_FAILED && s->state != PS_STATE_CLOSED)
        yes = s->inline_head != NULL;
    for (uint32_t i = 0; i < s->sf_count && !yes && s->state != PS_STATE_FAILED; i++) {
        const struct subflow *sf = &s->sf[i];
        if (!sf->used)
            continue;
        if (sf->need_connect || sf->close_pending)
            yes = 1;
        else if (sf->in_head && sf->in_head->ready)
            yes = 1;
        else if (frame_ready(sf) && !sf->read_paused)
            yes = 1;
    }
    unlock_s(s);
    return yes;
}

int ps_session_next_timeout_ms(const ps_session_t *session)
{
    if (!session)
        return 1000;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int t = 1000;
    if (s->state != PS_STATE_OPEN)
        t = 200;
    else if (s->scale_mode != PS_SCALE_FIXED && s->scale_inited) {
        uint64_t now = ps_now_ms();
        uint64_t due = s->last_scale_ms + s->scale_interval_ms;
        if (now >= due)
            t = 0;
        else {
            uint64_t d = due - now;
            t = d > 1000 ? 1000 : (int)d;
        }
    }
    unlock_s(s);
    return t;
}

static unsigned opening_count(const struct ps_session *s)
{
    unsigned n = 0;
    for (uint32_t i = 0; i < s->sf_count; i++) {
        int st = s->sf[i].state;
        if (s->sf[i].used && (st == SF_OPEN_SENT || st == SF_WAIT_TCP || st == SF_JOINING))
            n++;
    }
    return n;
}

void ps_session_scale_tick(ps_session_t *session)
{
    if (!session)
        return;
    lock_s(session);
    if (session->scale_mode == PS_SCALE_FIXED || !session->scale_inited ||
        session->state != PS_STATE_OPEN) {
        unlock_s(session);
        return;
    }
    uint64_t now = ps_now_ms();
    if (now < session->last_scale_ms + session->scale_interval_ms) {
        unlock_s(session);
        return;
    }
    uint64_t bytes = (session->app_tx + session->app_rx) - session->byte_mark;
    uint64_t interval = now - session->last_scale_ms;
    uint32_t rtt = 0;
    uint64_t retrans = 0;
    for (uint32_t i = 0; i < session->sf_count; i++) {
        if (session->sf[i].fd < 0)
            continue;
        uint32_t tr = 0;
        uint64_t rx = 0;
        if (ps_tcp_stats(session->sf[i].fd, &tr, &rx) == 0) {
            if (tr > rtt)
                rtt = tr;
            retrans += rx;
        }
    }
    if (rtt && (session->rtt_min == 0 || rtt < session->rtt_min))
        session->rtt_min = rtt;
    uint32_t rd = 0;
    if (retrans >= session->retrans_mark && retrans - session->retrans_mark < 0xffffffffull)
        rd = (uint32_t)(retrans - session->retrans_mark);
    struct ps_scale_sample sm;
    memset(&sm, 0, sizeof(sm));
    sm.bytes = bytes;
    sm.interval_ms = interval ? interval : 1;
    sm.rtt_us = rtt;
    sm.rtt_baseline_us = session->rtt_min;
    sm.retrans_delta = rd;
    sm.sockets = session->n_active ? session->n_active : 1;
    sm.min_sockets = session->min_sockets;
    sm.max_sockets = session->max_sockets;
    sm.demand = bytes > 0;
    sm.now_ms = now;
    sm.min_transfer_size = session->min_transfer_size;
    sm.advisory = session->scale_mode == PS_SCALE_ADVISORY;
    unsigned desired = ps_scale_step(&session->scale, &sm);
    session->last_scale_ms = now;
    session->byte_mark = session->app_tx + session->app_rx;
    session->retrans_mark = retrans;
    session->rtt_us = rtt;
    session->goodput_bps = interval ? bytes * 1000ull / interval : 0;
    if (session->is_server) {
        if (session->scale_mode == PS_SCALE_AUTO && desired != session->last_hint) {
            uint8_t body[4];
            ps_put_u32(body, desired);
            queue_ctrl_locked(session, SPT_CTRL_SCALE_REQUEST, body, sizeof(body));
            session->last_hint = desired;
        }
    } else if (session->scale_mode == PS_SCALE_AUTO) {
        apply_socket_target_locked(session, desired);
    }
    unlock_s(session);
    ps_session_progress(session);
}

int ps_session_wait_open(ps_session_t *session, uint32_t timeout_ms)
{
    if (!session)
        return -PS_ERR_INVAL;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ps_add_ms(&ts, timeout_ms);
    lock_s(session);
    while (session->state != PS_STATE_OPEN && session->state != PS_STATE_FAILED &&
           session->state != PS_STATE_CLOSED) {
        int rc = pthread_cond_timedwait(&session->cv, &session->mu, &ts);
        if ((rc == ETIMEDOUT || deadline_reached(&ts)) && session->state != PS_STATE_OPEN) {
            fail_locked(session, PS_ERR_TIMEOUT);
            break;
        }
    }
    int err = session->state == PS_STATE_OPEN ? PS_OK : (session->err ? session->err : PS_ERR_PROTO);
    unlock_s(session);
    ps_session_progress(session);
    return err ? -err : PS_OK;
}

ssize_t ps_session_send_wait(ps_session_t *session, const void *buf, size_t len,
                             uint8_t protection, uint32_t timeout_ms)
{
    if (!session || (!buf && len))
        return -PS_ERR_INVAL;
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    int fatal = PS_OK;
    struct timespec ts;
    int use_deadline = timeout_ms != UINT32_MAX;
    if (use_deadline) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ps_add_ms(&ts, timeout_ms);
    }
    while (left) {
        lock_s(session);
        int err = PS_OK;
        size_t n = submit_locked(session, p, left, protection, &err);
        int failed = session->state == PS_STATE_FAILED;
        if (failed)
            fatal = session->err ? session->err : PS_ERR_PROTO;
        unlock_s(session);
        if (n > 0) {
            p += n;
            left -= n;
            continue;
        }
        ps_session_progress_step(session);
        if (failed || (err != PS_ERR_AGAIN && err != PS_OK)) {
            fatal = fatal ? fatal : err;
            break;
        }
        lock_s(session);
        err = PS_OK;
        n = submit_locked(session, p, left, protection, &err);
        if (n == 0 && err == PS_ERR_AGAIN && session->state != PS_STATE_FAILED) {
            int rc = 0;
            if (use_deadline)
                rc = pthread_cond_timedwait(&session->cv, &session->mu, &ts);
            else
                pthread_cond_wait(&session->cv, &session->mu);
            if (rc == ETIMEDOUT || (use_deadline && deadline_reached(&ts)))
                fatal = PS_ERR_TIMEOUT;
        }
        if (session->state == PS_STATE_FAILED)
            fatal = session->err ? session->err : PS_ERR_PROTO;
        unlock_s(session);
        if (fatal)
            break;
        if (n > 0) {
            p += n;
            left -= n;
        }
    }
    ps_session_progress_step(session);
    if (left == len && fatal) {
        if (fatal != PS_ERR_AUTH && fatal != PS_ERR_INVAL) {
            lock_s(session);
            session->err = fatal;
            unlock_s(session);
        }
        return -fatal;
    }
    return (ssize_t)(len - left);
}

ssize_t ps_session_recv_wait(ps_session_t *session, void *buf, size_t len,
                             uint32_t timeout_ms)
{
    if (!session || (!buf && len))
        return -PS_ERR_INVAL;
    if (ps_session_inline_pending(session))
        ps_session_progress_step(session);
    struct timespec ts;
    int use_deadline = timeout_ms != UINT32_MAX;
    if (use_deadline) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ps_add_ms(&ts, timeout_ms);
    }
    lock_s(session);
    session->in_user_read = 1;
    for (;;) {
        if (session->state == PS_STATE_FAILED) {
            int err = session->err ? session->err : PS_ERR_PROTO;
            session->in_user_read = 0;
            session->err = err;
            unlock_s(session);
            return -err;
        }
        size_t full_bytes = 0;
        size_t total_bytes = 0;
        struct spt_seg *segs = spt_reassembly_take(&session->reassembly, (uint8_t *)buf,
                                                   len, &full_bytes, &total_bytes);
        if (total_bytes > 0) {
            session->app_rx += total_bytes;
            maybe_window_locked(session);
            session->in_user_read = 0;
            if (segs) {
                session->rx_hold++;
                unlock_s(session);
                size_t off = 0;
                for (struct spt_seg *seg = segs; seg; seg = seg->next) {
                    memcpy((uint8_t *)buf + off, seg->data + seg->skip, seg->len);
                    off += seg->len;
                }
                lock_s(session);
                spt_reassembly_recycle(&session->reassembly, segs);
                if (session->rx_hold)
                    session->rx_hold--;
                if (session->closing || session->state == PS_STATE_CLOSED)
                    pthread_cond_broadcast(&session->cv);
            }
            int need_dispatch = session->nacts > 0 || session->poke_pending;
            unlock_s(session);
            if (need_dispatch || ps_session_inline_pending(session))
                ps_session_progress_step(session);
            return (ssize_t)total_bytes;
        }
        if (eof_locked(session) || session->state == PS_STATE_CLOSED) {
            session->in_user_read = 0;
            unlock_s(session);
            return 0;
        }
        int rc = 0;
        if (use_deadline)
            rc = pthread_cond_timedwait(&session->cv, &session->mu, &ts);
        else
            pthread_cond_wait(&session->cv, &session->mu);
        if (rc == ETIMEDOUT || (use_deadline && deadline_reached(&ts))) {
            session->in_user_read = 0;
            session->err = PS_ERR_TIMEOUT;
            unlock_s(session);
            return -PS_ERR_TIMEOUT;
        }
    }
}

int ps_session_shutdown_write(ps_session_t *session)
{
    if (!session)
        return -PS_ERR_INVAL;
    lock_s(session);
    send_eos_locked(session);
    int err = session->state == PS_STATE_FAILED ? session->err : PS_OK;
    unlock_s(session);
    ps_session_progress(session);
    return err ? -err : PS_OK;
}

int ps_session_rekey_wait(ps_session_t *session, uint32_t timeout_ms)
{
    if (!session)
        return -PS_ERR_INVAL;
    lock_s(session);
    int started = 0;
    for (uint32_t i = 0; i < session->sf_count; i++) {
        if (session->sf[i].state == SF_ACTIVE && start_rekey_locked(session, &session->sf[i]) == 0)
            started = 1;
    }
    if (!started) {
        unlock_s(session);
        return -PS_ERR_INVAL;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ps_add_ms(&ts, timeout_ms);
    for (;;) {
        int pending = 0;
        if (session->state == PS_STATE_FAILED) {
            int err = session->err;
            unlock_s(session);
            return -err;
        }
        for (uint32_t i = 0; i < session->sf_count; i++) {
            if (session->sf[i].rekey_wait)
                pending = 1;
        }
        if (!pending)
            break;
        int rc = pthread_cond_timedwait(&session->cv, &session->mu, &ts);
        if (rc == ETIMEDOUT || deadline_reached(&ts)) {
            unlock_s(session);
            return -PS_ERR_TIMEOUT;
        }
    }
    unlock_s(session);
    ps_session_progress(session);
    return PS_OK;
}

int ps_embed_service(ps_session_t *session)
{
    if (!session)
        return -PS_ERR_INVAL;
    int closing[PS_MAX_SUBFLOWS];
    uint32_t connect_ids[PS_MAX_SUBFLOWS];
    int nclose = 0;
    int nconn = 0;
    lock_s(session);
    for (uint32_t i = 0; i < session->sf_count; i++) {
        struct subflow *sf = &session->sf[i];
        if (sf->close_pending && sf->fd >= 0) {
            closing[nclose++] = sf->fd;
            sf->fd = -1;
            sf->want_read = 0;
            sf->want_write = 0;
            sf->close_pending = 0;
        }
        if (sf->need_connect && sf->fd < 0 && !sf->connecting) {
            sf->need_connect = 0;
            sf->connecting = 1;
            connect_ids[nconn++] = sf->id;
        }
    }
    struct sockaddr_storage peer = session->peer;
    socklen_t peer_len = session->peer_len;
    unlock_s(session);
    dispatch(session);
    for (int i = 0; i < nclose; i++)
        close(closing[i]);
    for (int i = 0; i < nconn; i++) {
        if (peer_len == 0) {
            ps_session_fail(session, PS_ERR_INVAL);
            break;
        }
        int fd = -1;
        int rc = ps_tcp_connect_nb((struct sockaddr *)&peer, peer_len, &fd);
        lock_s(session);
        struct subflow *sf = sf_by_id(session, connect_ids[i]);
        if (!sf || session->closing) {
            unlock_s(session);
            if (fd >= 0)
                close(fd);
            continue;
        }
        if (rc < 0 || fd < 0) {
            fail_locked(session, PS_ERR_IO);
            unlock_s(session);
            break;
        }
        sf->fd = fd;
        if (rc == 1) {
            unlock_s(session);
            ps_session_on_connected(session, fd);
        } else {
            sf->want_write = 1;
            sf->want_read = 0;
            queue_io(session, fd, 0, 1);
            unlock_s(session);
        }
    }
    ps_session_progress(session);
    lock_s(session);
    int err = session->state == PS_STATE_FAILED ? session->err : PS_OK;
    unlock_s(session);
    return err ? -err : PS_OK;
}

unsigned ps_session_io_lanes(const ps_session_t *session)
{
    if (!session)
        return 1;
    unsigned n = ((const struct ps_session *)session)->initial_sockets;
    if (n < 1)
        n = 1;
    if (n > 16)
        n = 16;
    return n;
}

int ps_session_snap_fds(const ps_session_t *session, int *fds, int *data, int max)
{
    if (!session || !fds || !data || max <= 0)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int n = 0;
    if (s->ctrl_fd >= 0 && n < max) {
        fds[n] = s->ctrl_fd;
        data[n] = 0;
        n++;
    }
    for (uint32_t i = 0; i < s->sf_count && n < max; i++) {
        if (!s->sf[i].used || s->sf[i].fd < 0)
            continue;
        fds[n] = s->sf[i].fd;
        data[n] = 1;
        n++;
    }
    unlock_s(s);
    return n;
}

int ps_session_watches(const ps_session_t *session, struct ps_watch *out, int max)
{
    if (!session || !out || max <= 0)
        return 0;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int n = 0;
    if (s->ctrl_fd >= 0 && (s->ctrl_want_read || s->ctrl_want_write) && n < max) {
        out[n].fd = s->ctrl_fd;
        out[n].want_read = s->ctrl_want_read;
        out[n].want_write = s->ctrl_want_write;
        n++;
    }
    for (uint32_t i = 0; i < s->sf_count && n < max; i++) {
        if (s->sf[i].fd < 0)
            continue;
        if (!s->sf[i].want_read && !s->sf[i].want_write)
            continue;
        out[n].fd = s->sf[i].fd;
        out[n].want_read = s->sf[i].want_read;
        out[n].want_write = s->sf[i].want_write;
        n++;
    }
    unlock_s(s);
    return n;
}

static void fill_stats_locked(struct ps_session *s, struct ps_stats *out)
{
    memset(out, 0, sizeof(*out));
    out->app_bytes_sent = s->app_tx;
    out->app_bytes_recv = s->app_rx;
    out->records_sent = s->records_tx;
    out->records_recv = s->records_rx;
    out->active_sockets = s->n_active;
    out->opening_sockets = opening_count(s);
    out->reassembly_bytes = s->reassembly.buffered;
    out->goodput_bps = s->goodput_bps;
    out->rtt_us = s->rtt_us;
    out->peer_scale_request = s->peer_scale;
    out->last_error = s->err;
    out->frame_bytes = (uint32_t)s->frame_size;
}

static void fill_advice_locked(struct ps_session *s, struct ps_scale_advice *out)
{
    memset(out, 0, sizeof(*out));
    out->current_sockets = s->n_active;
    out->recommended_sockets = s->scale.recommended ? s->scale.recommended : s->n_active;
    out->goodput_bps = s->goodput_bps;
    out->rtt_us = s->rtt_us;
    out->congestion = s->scale.congestion;
    out->mode = s->scale_mode;
}

int ps_session_state(const ps_session_t *session)
{
    if (!session)
        return PS_STATE_CLOSED;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int st = s->state;
    unlock_s(s);
    return st;
}

int ps_session_error(const ps_session_t *session)
{
    if (!session)
        return PS_ERR_INVAL;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    int e = s->err;
    unlock_s(s);
    return e;
}

int ps_session_stats(const ps_session_t *session, struct ps_stats *out)
{
    if (!session || !out)
        return -PS_ERR_INVAL;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    fill_stats_locked(s, out);
    unlock_s(s);
    return PS_OK;
}

int ps_session_advice(const ps_session_t *session, struct ps_scale_advice *out)
{
    if (!session || !out)
        return -PS_ERR_INVAL;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    fill_advice_locked(s, out);
    unlock_s(s);
    return PS_OK;
}

int ps_submit_send(ps_session_t *session, const void *data, size_t length, size_t *accepted)
{
    if (!session || !accepted || (!data && length))
        return -PS_ERR_INVAL;
    lock_s(session);
    int err = PS_OK;
    size_t n = submit_locked(session, (const uint8_t *)data, length,
                             SPT_PROTECTION_CONFIDENTIAL, &err);
    *accepted = n;
    if (session->state == PS_STATE_FAILED)
        err = session->err ? session->err : PS_ERR_PROTO;
    unlock_s(session);
    ps_session_progress(session);
    if (n > 0)
        return PS_OK;
    return err ? -err : -PS_ERR_AGAIN;
}

int ps_submit_send_protected(ps_session_t *session, const struct ps_send_descriptor *desc,
                             size_t *accepted)
{
    if (!session || !desc || !accepted || (!desc->buffer && desc->length))
        return -PS_ERR_INVAL;
    lock_s(session);
    int err = PS_OK;
    size_t n = submit_locked(session, (const uint8_t *)desc->buffer, desc->length,
                             (uint8_t)desc->protection, &err);
    *accepted = n;
    if (session->state == PS_STATE_FAILED)
        err = session->err ? session->err : PS_ERR_PROTO;
    unlock_s(session);
    ps_session_progress(session);
    if (n > 0)
        return PS_OK;
    return err ? -err : -PS_ERR_AGAIN;
}

int ps_submit_recv(ps_session_t *session, void *data, size_t length, size_t *received)
{
    if (!session || !received || (!data && length))
        return -PS_ERR_INVAL;
    ps_session_progress(session);
    lock_s(session);
    session->in_user_read = 1;
    if (session->state == PS_STATE_FAILED) {
        int err = session->err ? session->err : PS_ERR_PROTO;
        session->in_user_read = 0;
        unlock_s(session);
        return -err;
    }
    size_t n = spt_reassembly_consume(&session->reassembly, (uint8_t *)data, length);
    if (n > 0) {
        session->app_rx += n;
        maybe_window_locked(session);
        *received = n;
        session->in_user_read = 0;
        unlock_s(session);
        ps_session_progress(session);
        return PS_OK;
    }
    int eof = eof_locked(session) || session->state == PS_STATE_CLOSED;
    session->in_user_read = 0;
    unlock_s(session);
    if (eof) {
        *received = 0;
        return PS_OK;
    }
    return -PS_ERR_AGAIN;
}

int ps_embed_set_data_port(ps_session_t *session, uint16_t port)
{
    if (!session || port == 0)
        return -PS_ERR_INVAL;
    lock_s(session);
    session->data_port = port;
    unlock_s(session);
    return PS_OK;
}

int ps_embed_set_peer(ps_session_t *session, const struct sockaddr *addr, socklen_t len)
{
    if (!session || !addr || len <= 0 || len > (socklen_t)sizeof(session->peer))
        return -PS_ERR_INVAL;
    lock_s(session);
    memset(&session->peer, 0, sizeof(session->peer));
    memcpy(&session->peer, addr, len);
    session->peer_len = len;
    unlock_s(session);
    return PS_OK;
}

int ps_embed_adopt_subflow(ps_session_t *session, uint32_t subflow_id, int fd)
{
    if (!session || fd < 0)
        return -PS_ERR_INVAL;
    if (ps_set_nonblock(fd) != 0)
        return -PS_ERR_IO;
    lock_s(session);
    if (session->closing || session->state == PS_STATE_FAILED) {
        unlock_s(session);
        return -PS_ERR_CLOSED;
    }
    struct subflow *sf = sf_by_id(session, subflow_id);
    if (!sf || sf->state != SF_WAIT_TCP || sf->fd >= 0) {
        unlock_s(session);
        return -PS_ERR_PROTO;
    }
    sf->fd = fd;
    sf->state = SF_JOINING;
    sf->connecting = 0;
    sf->want_read = 1;
    sf->want_write = 0;
    queue_io(session, fd, 1, 0);
    queue_poke(session);
    unlock_s(session);
    ps_session_progress(session);
    return PS_OK;
}

int ps_embed_session_id(const ps_session_t *session, uint8_t id[32])
{
    if (!session || !id)
        return -PS_ERR_INVAL;
    struct ps_session *s = (struct ps_session *)session;
    lock_s(s);
    if (!s->have_server_hello) {
        unlock_s(s);
        return -PS_ERR_AGAIN;
    }
    memcpy(id, s->session_id, 32);
    unlock_s(s);
    return PS_OK;
}

int ps_embed_shutdown_write(ps_session_t *session)
{
    return ps_session_shutdown_write(session);
}

void ps_embed_close(ps_session_t *session)
{
    if (!session)
        return;
    ps_session_mark_closing(session);
    ps_session_unregister_now(session);
    ps_session_stop_workers(session);
    ps_session_unref(session);
}

ps_session_t *ps_embed_create(int is_server, const struct ps_options *opt, const ps_io_cbs *cbs)
{
    const struct ps_tls_config *tls = opt ? opt->tls : NULL;
    SSL_CTX *ctx = is_server ? ps_tls_server_ctx(tls) : ps_tls_client_ctx(tls);
    if (!ctx)
        return NULL;
    return ps_session_create(is_server, opt, ctx, tls, cbs);
}

static int pending_out_locked(const struct ps_session *s)
{
    if (s->cout.len > s->cout.off || s->inline_head || s->jobs_inflight)
        return 1;
    for (uint32_t i = 0; i < s->sf_count; i++) {
        const struct subflow *sf = &s->sf[i];
        if (!sf->used)
            continue;
        if (sf->preface_off < sf->preface_len || sf->out_head)
            return 1;
    }
    return 0;
}

int ps_session_wait_flush(ps_session_t *session, uint32_t timeout_ms)
{
    if (!session)
        return -PS_ERR_INVAL;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ps_add_ms(&ts, timeout_ms);
    lock_s(session);
    while (pending_out_locked(session) && session->state != PS_STATE_FAILED) {
        int rc = pthread_cond_timedwait(&session->cv, &session->mu, &ts);
        if (rc == ETIMEDOUT || deadline_reached(&ts))
            break;
    }
    int pending = pending_out_locked(session);
    unlock_s(session);
    return pending ? -PS_ERR_TIMEOUT : PS_OK;
}

int ps_embed_set_control(ps_session_t *session, int fd)
{
    if (!session || fd < 0)
        return -PS_ERR_INVAL;
    ps_prepare_socket(fd);
    if (ps_set_nonblock(fd) != 0)
        return -PS_ERR_IO;
    SSL *ssl = ps_tls_wrap(session->ctx, fd, session->is_server, session->server_name);
    if (!ssl)
        return -PS_ERR_TLS;
    return ps_session_attach_ssl(session, ssl, fd, 0);
}

int ps_preface_read(int fd, uint8_t session_id[32], uint32_t *subflow_id, int timeout_ms)
{
    if (fd < 0 || !session_id || !subflow_id)
        return -PS_ERR_INVAL;
    uint8_t buf[SPT_PREFACE_LEN];
    if (ps_read_full(fd, buf, sizeof(buf), timeout_ms) != 0)
        return -PS_ERR_IO;
    if (spt_preface_decode(buf, subflow_id, session_id) != 0)
        return -PS_ERR_PROTO;
    return PS_OK;
}
