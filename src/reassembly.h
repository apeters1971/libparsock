#ifndef PARSOCK_REASSEMBLY_H
#define PARSOCK_REASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

struct spt_reassembly {
    uint64_t deliver;
    size_t limit;
    size_t buffered;
    struct spt_seg *head;
};

int spt_reassembly_init(struct spt_reassembly *r, size_t limit);
void spt_reassembly_free(struct spt_reassembly *r);
/* 0 ok, -1 conflict, -2 outside the receive window, -3 out of memory. */
int spt_reassembly_insert(struct spt_reassembly *r, uint64_t off,
                          const uint8_t *data, size_t len);
size_t spt_reassembly_available(const struct spt_reassembly *r);
size_t spt_reassembly_consume(struct spt_reassembly *r, uint8_t *dst, size_t cap);

#endif
