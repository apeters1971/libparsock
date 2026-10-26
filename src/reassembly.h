#ifndef PARSOCK_REASSEMBLY_H
#define PARSOCK_REASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

struct spt_seg {
    uint64_t off;
    size_t len;
    size_t skip;
    size_t cap;
    uint8_t *data;
    struct spt_seg *prev;
    struct spt_seg *next;
};

struct spt_buf_node {
    struct spt_buf_node *next;
};

struct spt_reassembly {
    uint64_t deliver;
    size_t limit;
    size_t buffered;
    size_t buf_size;
    struct spt_seg *head;
    struct spt_seg *tail;
    struct spt_seg *seg_pool;
    unsigned nsegs;
    struct spt_buf_node *buf_pool;
    unsigned nbufs;
};

int spt_reassembly_init(struct spt_reassembly *r, size_t limit);
void spt_reassembly_set_buf_size(struct spt_reassembly *r, size_t buf_size);
void spt_reassembly_free(struct spt_reassembly *r);
uint8_t *spt_reassembly_get_buf(struct spt_reassembly *r, size_t len, size_t *cap_out);
void spt_reassembly_put_buf(struct spt_reassembly *r, uint8_t *buf, size_t cap);
/* 0 ok, -1 conflict, -2 outside the receive window, -3 out of memory. */
int spt_reassembly_insert(struct spt_reassembly *r, uint64_t off,
                          const uint8_t *data, size_t len);
/* Takes ownership of data on every return, including errors. */
int spt_reassembly_adopt(struct spt_reassembly *r, uint64_t off, uint8_t *data, size_t len);
int spt_reassembly_adopt_pooled(struct spt_reassembly *r, uint64_t off,
                                uint8_t *data, size_t len, size_t cap);
size_t spt_reassembly_available(const struct spt_reassembly *r);
size_t spt_reassembly_consume(struct spt_reassembly *r, uint8_t *dst, size_t cap);
struct spt_seg *spt_reassembly_take(struct spt_reassembly *r, uint8_t *dst,
                                    size_t cap, size_t *full_bytes, size_t *total_bytes);
void spt_reassembly_recycle(struct spt_reassembly *r, struct spt_seg *segs);

#endif
