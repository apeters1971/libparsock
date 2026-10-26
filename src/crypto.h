#ifndef SPT_CRYPTO_H
#define SPT_CRYPTO_H

/*
 * AEAD helpers that keep an EVP_CIPHER_CTX alive across records.
 * One context is not safe to use from two threads at once.
 */

#include "spt_wire.h"

#include <openssl/evp.h>

EVP_CIPHER_CTX *spt_aead_ctx_new(void);
void spt_aead_ctx_free(EVP_CIPHER_CTX *ctx);

int spt_aead_seal_ctx(EVP_CIPHER_CTX *ctx,
                      uint16_t alg,
                      const uint8_t key[SPT_KEY_LEN],
                      const uint8_t static_iv[SPT_IV_LEN],
                      uint64_t record_sequence,
                      const uint8_t aad[SPT_FRAME_HEADER_LEN],
                      const uint8_t *plaintext,
                      size_t plaintext_len,
                      uint8_t *ciphertext,
                      uint8_t tag[SPT_TAG_LEN]);

int spt_aead_open_ctx(EVP_CIPHER_CTX *ctx,
                      uint16_t alg,
                      const uint8_t key[SPT_KEY_LEN],
                      const uint8_t static_iv[SPT_IV_LEN],
                      uint64_t record_sequence,
                      const uint8_t aad[SPT_FRAME_HEADER_LEN],
                      const uint8_t *ciphertext,
                      size_t ciphertext_len,
                      const uint8_t tag[SPT_TAG_LEN],
                      uint8_t *plaintext);

#endif
