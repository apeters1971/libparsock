#ifndef SPT_WIRE_H
#define SPT_WIRE_H

/*
 * SPT/0.1 wire definitions shared by every implementation.
 * Multi-byte integers are big-endian. No host structure layout is on the wire.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPT_PROTO_MAJOR 0
#define SPT_PROTO_MINOR 1

#define SPT_VERSION 1

#define SPT_FRAME_MAGIC 0x53505431u /* 'SPT1' */
#define SPT_PREFACE_MAGIC 0x5350544Au /* 'SPTJ' */

#define SPT_EXPORTER_LABEL "EXPORTER-libparsock-spt/0.1"
#define SPT_HKDF_SALT "spt-hkdf-salt-v1"
#define SPT_HKDF_INFO_PREFIX "spt-aead-v1"

#define SPT_ROOT_LEN 32
#define SPT_KEY_LEN 32
#define SPT_IV_LEN 12
#define SPT_TAG_LEN 16
#define SPT_RANDOM_LEN 32
#define SPT_SESSION_ID_LEN 32
#define SPT_NONCE_LEN 32
#define SPT_HASH_LEN 32
#define SPT_EXPORTER_CONTEXT_LEN (SPT_RANDOM_LEN * 2 + SPT_SESSION_ID_LEN)

#define SPT_FRAME_HEADER_LEN 40
#define SPT_PREFACE_LEN 44
#define SPT_JOIN_PLAIN_LEN 140
#define SPT_CLIENT_HELLO_LEN 64
#define SPT_SERVER_HELLO_LEN 92
#define SPT_SUBFLOW_HELLO_LEN 40
#define SPT_WINDOW_LEN 8
#define SPT_ID_LEN 4
#define SPT_KEY_UPDATE_LEN 8

#define SPT_MAX_PLAIN (256u * 1024u)
#define SPT_MAX_FRAME (SPT_FRAME_HEADER_LEN + SPT_MAX_PLAIN + SPT_TAG_LEN)
#define SPT_MAX_CTRL_BODY 65532u
#define SPT_MAX_CTRL_FRAME (4u + 4u + SPT_MAX_CTRL_BODY)

#define SPT_REKEY_RECORD_LIMIT (1ull << 20)

enum {
    SPT_AEAD_AES_256_GCM = 1,
    SPT_AEAD_CHACHA20_POLY1305 = 2
};

enum {
    SPT_DIR_C2S = 0,
    SPT_DIR_S2C = 1
};

enum {
    SPT_ROLE_CLIENT = 1,
    SPT_ROLE_SERVER = 2
};

enum {
    SPT_REC_DATA = 1,
    SPT_REC_JOIN = 2,
    SPT_REC_JOIN_ACK = 3,
    SPT_REC_SUBFLOW_END = 4,
    SPT_REC_EOS = 5
};

enum {
    SPT_FF_FIN = 0x0001
};

enum {
    SPT_CTRL_CLIENT_HELLO = 1,
    SPT_CTRL_SERVER_HELLO = 2,
    SPT_CTRL_SUBFLOW_OPEN = 3,
    SPT_CTRL_SUBFLOW_ACCEPT = 4,
    SPT_CTRL_SUBFLOW_REJECT = 5,
    SPT_CTRL_WINDOW_UPDATE = 6,
    SPT_CTRL_SUBFLOW_DRAIN = 7,
    SPT_CTRL_SUBFLOW_RETIRED = 8,
    SPT_CTRL_CLOSE = 9,
    SPT_CTRL_ERROR = 10,
    SPT_CTRL_SCALE_REQUEST = 11,
    SPT_CTRL_KEY_UPDATE = 12,
    SPT_CTRL_KEY_UPDATE_ACK = 13
};

enum {
    SPT_E_OK = 0,
    SPT_E_PROTO = 1,
    SPT_E_AUTH = 2,
    SPT_E_CRYPTO = 3,
    SPT_E_FLOW = 4,
    SPT_E_INTERNAL = 5,
    SPT_E_UNSUPPORTED = 6,
    SPT_E_CLOSED = 7,
    SPT_E_LIMIT = 8
};

struct spt_header {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t subflow_id;
    uint32_t key_generation;
    uint64_t record_sequence;
    uint64_t logical_offset;
    uint32_t plaintext_length;
};

struct spt_client_hello {
    uint16_t aead;
    uint32_t min_sockets;
    uint32_t max_sockets;
    uint32_t initial_sockets;
    uint32_t frame_size;
    uint64_t recv_window;
    uint32_t flags;
    uint8_t client_random[SPT_RANDOM_LEN];
};

struct spt_server_hello {
    uint16_t aead;
    uint32_t initial_sockets;
    uint32_t max_sockets;
    uint32_t frame_size;
    uint64_t recv_window;
    uint16_t data_port;
    uint8_t server_random[SPT_RANDOM_LEN];
    uint8_t session_id[SPT_SESSION_ID_LEN];
};

struct spt_subflow_hello {
    uint32_t subflow_id;
    uint32_t key_generation;
    uint8_t nonce[SPT_NONCE_LEN];
};

struct spt_join_plain {
    uint8_t role;
    uint32_t subflow_id;
    uint32_t key_generation;
    uint8_t session_id[SPT_SESSION_ID_LEN];
    uint8_t client_nonce[SPT_NONCE_LEN];
    uint8_t server_nonce[SPT_NONCE_LEN];
    uint8_t hello_hash[SPT_HASH_LEN];
};

size_t spt_frame_wire_len(uint32_t plaintext_length);

int spt_header_encode(uint8_t out[SPT_FRAME_HEADER_LEN], const struct spt_header *hdr);
int spt_header_decode(const uint8_t in[SPT_FRAME_HEADER_LEN], struct spt_header *hdr);

int spt_ctrl_encode(uint8_t *out, size_t cap, uint16_t type,
                    const uint8_t *body, size_t body_len, size_t *written);
int spt_ctrl_peek(const uint8_t *in, size_t len, uint16_t *type,
                  const uint8_t **body, size_t *body_len, size_t *consumed);

int spt_client_hello_encode(uint8_t out[SPT_CLIENT_HELLO_LEN],
                            const struct spt_client_hello *msg);
int spt_client_hello_decode(const uint8_t in[SPT_CLIENT_HELLO_LEN],
                            struct spt_client_hello *msg);
int spt_server_hello_encode(uint8_t out[SPT_SERVER_HELLO_LEN],
                            const struct spt_server_hello *msg);
int spt_server_hello_decode(const uint8_t in[SPT_SERVER_HELLO_LEN],
                            struct spt_server_hello *msg);
int spt_subflow_hello_encode(uint8_t out[SPT_SUBFLOW_HELLO_LEN],
                             const struct spt_subflow_hello *msg);
int spt_subflow_hello_decode(const uint8_t in[SPT_SUBFLOW_HELLO_LEN],
                             struct spt_subflow_hello *msg);

int spt_preface_encode(uint8_t out[SPT_PREFACE_LEN], uint32_t subflow_id,
                       const uint8_t session_id[SPT_SESSION_ID_LEN]);
int spt_preface_decode(const uint8_t in[SPT_PREFACE_LEN], uint32_t *subflow_id,
                       uint8_t session_id[SPT_SESSION_ID_LEN]);

int spt_join_encode(uint8_t out[SPT_JOIN_PLAIN_LEN], const struct spt_join_plain *msg);
int spt_join_decode(const uint8_t in[SPT_JOIN_PLAIN_LEN], struct spt_join_plain *msg);

void spt_nonce(uint8_t out[SPT_IV_LEN], const uint8_t static_iv[SPT_IV_LEN],
               uint64_t record_sequence);

int spt_derive_aead_key(const uint8_t root[SPT_ROOT_LEN],
                        uint8_t direction,
                        uint32_t subflow_id,
                        uint32_t generation,
                        uint16_t aead_alg,
                        const uint8_t client_nonce[SPT_NONCE_LEN],
                        const uint8_t server_nonce[SPT_NONCE_LEN],
                        const uint8_t session_id[SPT_SESSION_ID_LEN],
                        uint8_t key[SPT_KEY_LEN],
                        uint8_t static_iv[SPT_IV_LEN]);

int spt_aead_seal(uint16_t alg,
                  const uint8_t key[SPT_KEY_LEN],
                  const uint8_t static_iv[SPT_IV_LEN],
                  uint64_t record_sequence,
                  const uint8_t aad[SPT_FRAME_HEADER_LEN],
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  uint8_t *ciphertext,
                  uint8_t tag[SPT_TAG_LEN]);

int spt_aead_open(uint16_t alg,
                  const uint8_t key[SPT_KEY_LEN],
                  const uint8_t static_iv[SPT_IV_LEN],
                  uint64_t record_sequence,
                  const uint8_t aad[SPT_FRAME_HEADER_LEN],
                  const uint8_t *ciphertext,
                  size_t ciphertext_len,
                  const uint8_t tag[SPT_TAG_LEN],
                  uint8_t *plaintext);

int spt_sha256(const uint8_t *data, size_t len, uint8_t out[SPT_HASH_LEN]);

void spt_exporter_context(uint8_t out[SPT_EXPORTER_CONTEXT_LEN],
                          const uint8_t client_random[SPT_RANDOM_LEN],
                          const uint8_t server_random[SPT_RANDOM_LEN],
                          const uint8_t session_id[SPT_SESSION_ID_LEN]);

#ifdef __cplusplus
}
#endif

#endif
