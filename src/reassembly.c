#include "reassembly.h"

#include <stdlib.h>
#include <string.h>

struct spt_seg {
    uint64_t off;
    size_t len;
    uint8_t *data;
    struct spt_seg *next;
};

int spt_reassembly_init(struct spt_reassembly *r, size_t limit)
{
    if (!r || limit == 0)
        return -1;
    memset(r, 0, sizeof(*r));
    r->limit = limit;
    return 0;
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
    r->buffered = 0;
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
        struct spt_seg *prev = NULL;
        struct spt_seg *cur = r->head;
        while (cur && cur->off + cur->len <= off) {
            prev = cur;
            cur = cur->next;
        }
        if (cur && cur->off <= off) {
            uint64_t end = cur->off + cur->len;
            size_t overlap = (size_t)((end - off) > len ? len : (end - off));
            if (memcmp(cur->data + (size_t)(off - cur->off), data, overlap) != 0)
                return -1;
            off += overlap;
            data += overlap;
            len -= overlap;
            continue;
        }
        size_t room = len;
        if (cur && off + (uint64_t)room > cur->off)
            room = (size_t)(cur->off - off);
        struct spt_seg *seg = (struct spt_seg *)calloc(1, sizeof(*seg));
        if (!seg)
            return -3;
        seg->data = (uint8_t *)malloc(room);
        if (!seg->data) {
            free(seg);
            return -3;
        }
        memcpy(seg->data, data, room);
        seg->off = off;
        seg->len = room;
        seg->next = cur;
        if (prev)
            prev->next = seg;
        else
            r->head = seg;
        r->buffered += room;
        off += room;
        data += room;
        len -= room;
    }
    return 0;
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
        memcpy(dst + got, r->head->data, n);
        got += n;
        r->deliver += n;
        r->buffered -= n;
        if (n == r->head->len) {
            struct spt_seg *dead = r->head;
            r->head = dead->next;
            free(dead->data);
            free(dead);
        } else {
            memmove(r->head->data, r->head->data + n, r->head->len - n);
            r->head->off += n;
            r->head->len -= n;
        }
    }
    return got;
}
