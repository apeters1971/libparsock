#include "reassembly.h"

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

int main(void)
{
    struct spt_reassembly r;
    expect(spt_reassembly_init(&r, 16) == 0, "init");
    expect(spt_reassembly_insert(&r, 4, (const uint8_t *)"WXYZ", 4) == 0, "gap");
    expect(spt_reassembly_available(&r) == 0, "not ready");
    expect(spt_reassembly_insert(&r, 0, (const uint8_t *)"ABCD", 4) == 0, "head");
    expect(spt_reassembly_available(&r) == 8, "coalesced");
    uint8_t out[16];
    expect(spt_reassembly_consume(&r, out, 3) == 3, "partial consume");
    expect(memcmp(out, "ABC", 3) == 0, "partial bytes");
    expect(spt_reassembly_available(&r) == 5, "rest");
    expect(spt_reassembly_insert(&r, 0, (const uint8_t *)"ABC", 3) == 0, "old duplicate");
    expect(spt_reassembly_insert(&r, 3, (const uint8_t *)"DXXXX", 5) != 0, "conflict");
    expect(spt_reassembly_insert(&r, 3, (const uint8_t *)"DWXYZ", 5) == 0, "identical overlap");
    expect(spt_reassembly_consume(&r, out, 16) == 5 && memcmp(out, "DWXYZ", 5) == 0, "rest bytes");
    expect(spt_reassembly_insert(&r, 8, (const uint8_t *)"0123456789abcdefX", 17) == -2, "window");
    expect(spt_reassembly_insert(&r, 8, (const uint8_t *)"01234567", 8) == 0, "in window");
    spt_reassembly_free(&r);
    if (fails) {
        fprintf(stderr, "%d reassembly checks failed\n", fails);
        return 1;
    }
    return 0;
}
