#ifndef PARSOCK_ENDIAN_H
#define PARSOCK_ENDIAN_H

#include <stdint.h>
#include <string.h>

static inline void ps_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void ps_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void ps_put_u64(uint8_t *p, uint64_t v)
{
    ps_put_u32(p, (uint32_t)(v >> 32));
    ps_put_u32(p + 4, (uint32_t)v);
}

static inline uint16_t ps_get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t ps_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t ps_get_u64(const uint8_t *p)
{
    return ((uint64_t)ps_get_u32(p) << 32) | ps_get_u32(p + 4);
}

static inline int ps_memeq(const void *a, const void *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

#endif
