#include "spt_wire.h"

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static int fails;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "fail: %s\n", msg);
        fails++;
    }
}

static int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                       uint8_t out[32])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()
    };
    size_t outl = 0;
    int ok = ctx &&
             EVP_MAC_init(ctx, key, key_len, params) == 1 &&
             EVP_MAC_update(ctx, data, data_len) == 1 &&
             EVP_MAC_final(ctx, out, &outl, 32) == 1 &&
             outl == 32;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok ? 0 : -1;
}

static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len)
{
    uint8_t prk[32];
    if (hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != 0)
        return -1;
    uint8_t prev[32];
    size_t prev_len = 0;
    size_t off = 0;
    uint8_t counter = 1;
    while (off < okm_len) {
        uint8_t block[32 + 256];
        if (prev_len + info_len + 1 > sizeof(block))
            return -1;
        size_t bl = 0;
        if (prev_len) {
            memcpy(block, prev, prev_len);
            bl = prev_len;
        }
        memcpy(block + bl, info, info_len);
        bl += info_len;
        block[bl++] = counter++;
        if (hmac_sha256(prk, 32, block, bl, prev) != 0)
            return -1;
        prev_len = 32;
        size_t take = okm_len - off;
        if (take > 32)
            take = 32;
        memcpy(okm + off, prev, take);
        off += take;
    }
    return 0;
}

static void fill_info(uint8_t *info, size_t *len, uint8_t dir, uint32_t sf, uint32_t gen,
                      uint16_t aead, const uint8_t *cn, const uint8_t *sn, const uint8_t *sid)
{
    size_t off = sizeof(SPT_HKDF_INFO_PREFIX) - 1;
    memcpy(info, SPT_HKDF_INFO_PREFIX, off);
    info[off++] = dir;
    info[off++] = (uint8_t)(sf >> 24);
    info[off++] = (uint8_t)(sf >> 16);
    info[off++] = (uint8_t)(sf >> 8);
    info[off++] = (uint8_t)sf;
    info[off++] = (uint8_t)(gen >> 24);
    info[off++] = (uint8_t)(gen >> 16);
    info[off++] = (uint8_t)(gen >> 8);
    info[off++] = (uint8_t)gen;
    info[off++] = (uint8_t)(aead >> 8);
    info[off++] = (uint8_t)aead;
    memcpy(info + off, cn, 32);
    off += 32;
    memcpy(info + off, sn, 32);
    off += 32;
    memcpy(info + off, sid, 32);
    off += 32;
    *len = off;
}

static void roundtrip(uint16_t alg, const char *name)
{
    uint8_t root[32], cn[32], sn[32], sid[32];
    for (int i = 0; i < 32; i++) {
        root[i] = (uint8_t)(i + 1);
        cn[i] = (uint8_t)(0x40 + i);
        sn[i] = (uint8_t)(0x80 + i);
        sid[i] = (uint8_t)(0xc0 + i);
    }
    uint8_t key[32], iv[12], key2[32], iv2[12];
    expect(spt_derive_aead_key(root, SPT_DIR_C2S, 3, 1, alg, cn, sn, sid, key, iv) == 0, name);
    uint8_t info[128];
    size_t ilen = 0;
    fill_info(info, &ilen, SPT_DIR_C2S, 3, 1, alg, cn, sn, sid);
    uint8_t okm[44];
    expect(hkdf_sha256(root, 32, (const uint8_t *)SPT_HKDF_SALT, sizeof(SPT_HKDF_SALT) - 1, info,
                       ilen, okm, sizeof(okm)) == 0,
           "hkdf");
    expect(memcmp(key, okm, 32) == 0 && memcmp(iv, okm + 32, 12) == 0, "hkdf match");
    expect(spt_derive_aead_key(root, SPT_DIR_S2C, 3, 1, alg, cn, sn, sid, key2, iv2) == 0,
           "other dir");
    expect(memcmp(key, key2, 32) != 0, "direction separation");

    uint8_t nonce[12];
    spt_nonce(nonce, iv, 0x0102030405060708ull);
    expect(nonce[0] == iv[0] && nonce[1] == iv[1] && nonce[2] == iv[2] && nonce[3] == iv[3],
           "nonce high");
    expect(nonce[4] == (uint8_t)(iv[4] ^ 0x01), "nonce seq");

    uint8_t aad[SPT_FRAME_HEADER_LEN];
    memset(aad, 0x5a, sizeof(aad));
    uint8_t pt[32];
    for (int i = 0; i < 32; i++)
        pt[i] = (uint8_t)i;
    uint8_t ct[32], tag[16], out[32];
    expect(spt_aead_seal(alg, key, iv, 7, aad, pt, sizeof(pt), ct, tag) == 0, "seal");
    expect(spt_aead_open(alg, key, iv, 7, aad, ct, sizeof(ct), tag, out) == 0, "open");
    expect(memcmp(pt, out, sizeof(pt)) == 0, "plaintext");
    tag[0] ^= 1;
    expect(spt_aead_open(alg, key, iv, 7, aad, ct, sizeof(ct), tag, out) != 0, "tamper tag");
    tag[0] ^= 1;
    ct[3] ^= 1;
    expect(spt_aead_open(alg, key, iv, 7, aad, ct, sizeof(ct), tag, out) != 0, "tamper ct");
    expect(spt_aead_seal(alg, key, iv, 9, aad, NULL, 0, NULL, tag) == 0, "empty seal");
    expect(spt_aead_open(alg, key, iv, 9, aad, NULL, 0, tag, NULL) == 0, "empty open");
    uint8_t hash[32];
    expect(spt_sha256((const uint8_t *)"abc", 3, hash) == 0, "sha");
    static const uint8_t abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    expect(memcmp(hash, abc, 32) == 0, "sha abc");
}

int main(void)
{
    roundtrip(SPT_AEAD_AES_256_GCM, "aes derive");
    roundtrip(SPT_AEAD_CHACHA20_POLY1305, "chacha derive");
    if (fails) {
        fprintf(stderr, "%d crypto checks failed\n", fails);
        return 1;
    }
    return 0;
}
