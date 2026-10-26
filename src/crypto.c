#include "spt_wire.h"

#include "endian.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <string.h>

int spt_sha256(const uint8_t *data, size_t len, uint8_t out[SPT_HASH_LEN])
{
    if (!out || (len > 0 && !data))
        return -1;
    unsigned int outl = 0;
    if (EVP_Digest(data, len, out, &outl, EVP_sha256(), NULL) != 1 || outl != SPT_HASH_LEN)
        return -1;
    return 0;
}

void spt_exporter_context(uint8_t out[SPT_EXPORTER_CONTEXT_LEN],
                          const uint8_t client_random[SPT_RANDOM_LEN],
                          const uint8_t server_random[SPT_RANDOM_LEN],
                          const uint8_t session_id[SPT_SESSION_ID_LEN])
{
    memcpy(out, client_random, SPT_RANDOM_LEN);
    memcpy(out + SPT_RANDOM_LEN, server_random, SPT_RANDOM_LEN);
    memcpy(out + SPT_RANDOM_LEN * 2, session_id, SPT_SESSION_ID_LEN);
}

void spt_nonce(uint8_t out[SPT_IV_LEN], const uint8_t static_iv[SPT_IV_LEN],
               uint64_t record_sequence)
{
    uint8_t enc[SPT_IV_LEN];
    memset(enc, 0, sizeof(enc));
    ps_put_u64(enc + 4, record_sequence);
    for (int i = 0; i < SPT_IV_LEN; i++)
        out[i] = (uint8_t)(static_iv[i] ^ enc[i]);
}

static const EVP_CIPHER *cipher_for(uint16_t alg)
{
    if (alg == SPT_AEAD_AES_256_GCM)
        return EVP_aes_256_gcm();
    if (alg == SPT_AEAD_CHACHA20_POLY1305)
        return EVP_chacha20_poly1305();
    return NULL;
}

int spt_derive_aead_key(const uint8_t root[SPT_ROOT_LEN],
                        uint8_t direction,
                        uint32_t subflow_id,
                        uint32_t generation,
                        uint16_t aead_alg,
                        const uint8_t client_nonce[SPT_NONCE_LEN],
                        const uint8_t server_nonce[SPT_NONCE_LEN],
                        const uint8_t session_id[SPT_SESSION_ID_LEN],
                        uint8_t key[SPT_KEY_LEN],
                        uint8_t static_iv[SPT_IV_LEN])
{
    if (!root || !client_nonce || !server_nonce || !session_id || !key || !static_iv)
        return -1;
    if (direction > SPT_DIR_S2C || cipher_for(aead_alg) == NULL)
        return -1;

    uint8_t info[11 + 1 + 4 + 4 + 2 + SPT_NONCE_LEN + SPT_NONCE_LEN + SPT_SESSION_ID_LEN];
    size_t prefix_len = sizeof(SPT_HKDF_INFO_PREFIX) - 1;
    memcpy(info, SPT_HKDF_INFO_PREFIX, prefix_len);
    size_t off = prefix_len;
    info[off++] = direction;
    ps_put_u32(info + off, subflow_id);
    off += 4;
    ps_put_u32(info + off, generation);
    off += 4;
    ps_put_u16(info + off, aead_alg);
    off += 2;
    memcpy(info + off, client_nonce, SPT_NONCE_LEN);
    off += SPT_NONCE_LEN;
    memcpy(info + off, server_nonce, SPT_NONCE_LEN);
    off += SPT_NONCE_LEN;
    memcpy(info + off, session_id, SPT_SESSION_ID_LEN);
    off += SPT_SESSION_ID_LEN;

    static const char salt[] = SPT_HKDF_SALT;
    uint8_t okm[SPT_KEY_LEN + SPT_IV_LEN];
    int rc = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!ctx)
        goto done;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)root, SPT_ROOT_LEN),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, sizeof(salt) - 1),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, off),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(ctx, okm, sizeof(okm), params) != 1)
        goto done;
    memcpy(key, okm, SPT_KEY_LEN);
    memcpy(static_iv, okm + SPT_KEY_LEN, SPT_IV_LEN);
    rc = 0;
done:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(okm, sizeof(okm));
    OPENSSL_cleanse(info, sizeof(info));
    return rc;
}

int spt_aead_seal(uint16_t alg,
                  const uint8_t key[SPT_KEY_LEN],
                  const uint8_t static_iv[SPT_IV_LEN],
                  uint64_t record_sequence,
                  const uint8_t aad[SPT_FRAME_HEADER_LEN],
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  uint8_t *ciphertext,
                  uint8_t tag[SPT_TAG_LEN])
{
    const EVP_CIPHER *cipher = cipher_for(alg);
    if (!cipher || !key || !static_iv || !aad || !tag)
        return -1;
    if (plaintext_len > 0 && (!plaintext || !ciphertext))
        return -1;
    if (plaintext_len > SPT_MAX_PLAIN)
        return -1;

    uint8_t nonce[SPT_IV_LEN];
    spt_nonce(nonce, static_iv, record_sequence);
    int rc = -1;
    int len = 0;
    int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto done;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, SPT_IV_LEN, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, SPT_FRAME_HEADER_LEN) != 1)
        goto done;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1)
            goto done;
        if ((size_t)len != plaintext_len)
            goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext ? ciphertext + plaintext_len : NULL, &outl) != 1)
        goto done;
    if (outl != 0)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SPT_TAG_LEN, tag) != 1)
        goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return rc;
}

int spt_aead_open(uint16_t alg,
                  const uint8_t key[SPT_KEY_LEN],
                  const uint8_t static_iv[SPT_IV_LEN],
                  uint64_t record_sequence,
                  const uint8_t aad[SPT_FRAME_HEADER_LEN],
                  const uint8_t *ciphertext,
                  size_t ciphertext_len,
                  const uint8_t tag[SPT_TAG_LEN],
                  uint8_t *plaintext)
{
    const EVP_CIPHER *cipher = cipher_for(alg);
    if (!cipher || !key || !static_iv || !aad || !tag)
        return -1;
    if (ciphertext_len > SPT_MAX_PLAIN)
        return -1;
    if (ciphertext_len > 0 && (!ciphertext || !plaintext))
        return -1;

    uint8_t nonce[SPT_IV_LEN];
    spt_nonce(nonce, static_iv, record_sequence);
    int rc = -1;
    int len = 0;
    int outl = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto done;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, SPT_IV_LEN, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, SPT_FRAME_HEADER_LEN) != 1)
        goto done;
    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1)
            goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SPT_TAG_LEN, (void *)tag) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(ctx, plaintext ? plaintext + (ciphertext_len > 0 ? len : 0) : NULL,
                            &outl) != 1)
        goto done;
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return rc;
}
