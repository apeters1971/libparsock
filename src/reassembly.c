#include "reassembly.h"

#include <stdlib.h>
#include <string.h>

#define SEG_POOL_MAX 4096
#define BUF_POOL_MAX 2048

static struct spt_seg *seg_get(struct spt_reassembly *r)
{
    if (r->seg_pool) {
        struct spt_seg *s = r->seg_pool;
        r->seg_pool = s->next;
        if (r->nsegs)
            r->nsegs--;
        memset(s, 0, sizeof(*s));
        return s;
    }
    return (struct spt_seg *)calloc(1, sizeof(struct spt_seg));
}

static void seg_put(struct spt_reassembly *r, struct spt_seg *s)
{
    if (!s)
        return;
    if (r->nsegs < SEG_POOL_MAX) {
        s->prev = NULL;
        s->next = r->seg_pool;
        r->seg_pool = s;
        r->nsegs++;
        return;
    }
    free(s);
}

uint8_t *spt_reassembly_get_buf(struct spt_reassembly *r, size_t len, size_t *cap_out)
{
    size_t need = len ? len : 1;
    if (r && r->buf_size >= sizeof(struct spt_buf_node) && need <= r->buf_size) {
        if (cap_out)
            *cap_out = r->buf_size;
        if (r->buf_pool) {
            struct spt_buf_node *n = r->buf_pool;
            r->buf_pool = n->next;
            if (r->nbufs)
                r->nbufs--;
            return (uint8_t *)n;
        }
        return (uint8_t *)malloc(r->buf_size);
    }
    if (cap_out)
        *cap_out = 0;
    return (uint8_t *)malloc(need);
}

void spt_reassembly_put_buf(struct spt_reassembly *r, uint8_t *buf, size_t cap)
{
    if (!buf)
        return;
    if (r && cap > 0 && cap == r->buf_size && cap >= sizeof(struct spt_buf_node) &&
        r->nbufs < BUF_POOL_MAX) {
        struct spt_buf_node *n = (struct spt_buf_node *)buf;
        n->next = r->buf_pool;
        r->buf_pool = n;
        r->nbufs++;
        return;
    }
    free(buf);
}

int spt_reassembly_init(struct spt_reassembly *r, size_t limit)
{
    if (!r || limit == 0)
        return -1;
    memset(r, 0, sizeof(*r));
    r->limit = limit;
    return 0;
}

void spt_reassembly_set_buf_size(struct spt_reassembly *r, size_t buf_size)
{
    if (!r)
        return;
    r->buf_size = buf_size;
}

void spt_reassembly_free(struct spt_reassembly *r)
{
    if (!r)
        return;
    struct spt_seg *s = r->head;
    while (s) {
        struct spt_seg *n = s->next;
        free(s->data);
        free(s);
        s = n;
    }
    r->head = NULL;
    r->tail = NULL;
    r->buffered = 0;
    while (r->seg_pool) {
        struct spt_seg *n = r->seg_pool;
        r->seg_pool = n->next;
        free(n);
    }
    r->nsegs = 0;
    while (r->buf_pool) {
        struct spt_buf_node *n = r->buf_pool;
        r->buf_pool = n->next;
        free(n);
    }
    r->nbufs = 0;
}

static void link_seg(struct spt_reassembly *r, struct spt_seg *prev,
                     struct spt_seg *cur, struct spt_seg *seg)
{
    seg->prev = prev;
    seg->next = cur;
    if (prev)
        prev->next = seg;
    else
        r->head = seg;
    if (cur)
        cur->prev = seg;
    else
        r->tail = seg;
}

int spt_reassembly_insert(struct spt_reassembly *r, uint64_t off,
                          const uint8_t *data, size_t len)
{
    if (!r || (len > 0 && !data))
        return -1;
    if (len == 0)
        return 0;
    if (off + (uint64_t)len < off)
        return -1;
    if (off < r->deliver) {
        uint64_t skip = r->deliver - off;
        if (skip >= len)
            return 0;
        off += skip;
        data += skip;
        len -= (size_t)skip;
    }
    if (off + (uint64_t)len > r->deliver + (uint64_t)r->limit)
        return -2;

    while (len > 0) {
        struct spt_seg *prev = r->tail;
        while (prev && prev->off + prev->len > off)
            prev = prev->prev;
        struct spt_seg *cur = prev ? prev->next : r->head;
        if (cur && cur->off <= off) {
            uint64_t end = cur->off + cur->len;
            size_t overlap = (size_t)((end - off) > len ? len : (end - off));
            if (memcmp(cur->data + cur->skip + (size_t)(off - cur->off), data, overlap) != 0)
                return -1;
            off += overlap;
            data += overlap;
            len -= overlap;
            continue;
        }
        size_t room = len;
        if (cur && off + (uint64_t)room > cur->off)
            room = (size_t)(cur->off - off);
        struct spt_seg *seg = seg_get(r);
        if (!seg)
            return -3;
        size_t cap = 0;
        seg->data = spt_reassembly_get_buf(r, room, &cap);
        if (!seg->data) {
            seg_put(r, seg);
            return -3;
        }
        seg->cap = cap;
        memcpy(seg->data, data, room);
        seg->off = off;
        seg->len = room;
        link_seg(r, prev, cur, seg);
        r->buffered += room;
        off += room;
        data += room;
        len -= room;
    }
    return 0;
}

int spt_reassembly_adopt_pooled(struct spt_reassembly *r, uint64_t off,
                                uint8_t *data, size_t len, size_t cap)
{
    if (!r || (len > 0 && !data)) {
        spt_reassembly_put_buf(r, data, cap);
        return -1;
    }
    if (len == 0 || off + (uint64_t)len < off) {
        spt_reassembly_put_buf(r, data, cap);
        return len == 0 ? 0 : -1;
    }
    if (off < r->deliver || off + (uint64_t)len > r->deliver + (uint64_t)r->limit) {
        int rc = spt_reassembly_insert(r, off, data, len);
        spt_reassembly_put_buf(r, data, cap);
        return rc;
    }
    struct spt_seg *prev = r->tail;
    while (prev && prev->off + prev->len > off)
        prev = prev->prev;
    struct spt_seg *cur = prev ? prev->next : r->head;
    if ((cur && cur->off < off + (uint64_t)len) || (prev && prev->off + prev->len > off)) {
        int rc = spt_reassembly_insert(r, off, data, len);
        spt_reassembly_put_buf(r, data, cap);
        return rc;
    }
    struct spt_seg *seg = seg_get(r);
    if (!seg) {
        spt_reassembly_put_buf(r, data, cap);
        return -3;
    }
    seg->data = data;
    seg->cap = cap;
    seg->off = off;
    seg->len = len;
    link_seg(r, prev, cur, seg);
    r->buffered += len;
    return 0;
}

int spt_reassembly_adopt(struct spt_reassembly *r, uint64_t off, uint8_t *data, size_t len)
{
    return spt_reassembly_adopt_pooled(r, off, data, len, 0);
}

size_t spt_reassembly_available(const struct spt_reassembly *r)
{
    if (!r || !r->head || r->head->off != r->deliver)
        return 0;
    size_t n = 0;
    uint64_t at = r->deliver;
    for (const struct spt_seg *s = r->head; s && s->off == at; s = s->next) {
        n += s->len;
        at += s->len;
    }
    return n;
}

size_t spt_reassembly_consume(struct spt_reassembly *r, uint8_t *dst, size_t cap)
{
    if (!r || (cap > 0 && !dst))
        return 0;
    size_t got = 0;
    while (got < cap && r->head && r->head->off == r->deliver) {
        size_t n = r->head->len;
        if (n > cap - got)
            n = cap - got;
        memcpy(dst + got, r->head->data + r->head->skip, n);
        got += n;
        r->deliver += n;
        r->buffered -= n;
        if (n == r->head->len) {
            struct spt_seg *dead = r->head;
            r->head = dead->next;
            if (r->head)
                r->head->prev = NULL;
            else
                r->tail = NULL;
            spt_reassembly_put_buf(r, dead->data, dead->cap);
            seg_put(r, dead);
        } else {
            r->head->skip += n;
            r->head->off += n;
            r->head->len -= n;
        }
    }
    return got;
}

struct spt_seg *spt_reassembly_take(struct spt_reassembly *r, uint8_t *dst,
                                    size_t cap, size_t *full_bytes, size_t *total_bytes)
{
    if (full_bytes)
        *full_bytes = 0;
    if (total_bytes)
        *total_bytes = 0;
    if (!r || (cap > 0 && !dst))
        return NULL;
    struct spt_seg *taken_head = NULL;
    struct spt_seg *taken_tail = NULL;
    size_t full = 0;
    size_t got = 0;
    while (got < cap && r->head && r->head->off == r->deliver) {
        struct spt_seg *h = r->head;
        size_t n = h->len;
        if (n <= cap - got) {
            r->head = h->next;
            if (r->head)
                r->head->prev = NULL;
            else
                r->tail = NULL;
            h->prev = NULL;
            h->next = NULL;
            if (taken_tail)
                taken_tail->next = h;
            else
                taken_head = h;
            taken_tail = h;
            full += n;
            got += n;
            r->deliver += n;
            r->buffered -= n;
        } else {
            size_t part = cap - got;
            memcpy(dst + got, h->data + h->skip, part);
            h->skip += part;
            h->off += part;
            h->len -= part;
            got += part;
            r->deliver += part;
            r->buffered -= part;
            break;
        }
    }
    if (full_bytes)
        *full_bytes = full;
    if (total_bytes)
        *total_bytes = got;
    return taken_head;
}

void spt_reassembly_recycle(struct spt_reassembly *r, struct spt_seg *segs)
{
    while (segs) {
        struct spt_seg *next = segs->next;
        spt_reassembly_put_buf(r, segs->data, segs->cap);
        seg_put(r, segs);
        segs = next;
    }
}
