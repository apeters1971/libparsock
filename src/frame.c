#include "spt_wire.h"

#include "endian.h"

#include <string.h>

size_t spt_frame_wire_len(uint32_t plaintext_length)
{
    return (size_t)SPT_FRAME_HEADER_LEN + (size_t)plaintext_length + SPT_TAG_LEN;
}

int spt_header_encode(uint8_t out[SPT_FRAME_HEADER_LEN], const struct spt_header *hdr)
{
    if (!out || !hdr)
        return -1;
    memset(out, 0, SPT_FRAME_HEADER_LEN);
    ps_put_u32(out + 0, SPT_FRAME_MAGIC);
    out[4] = hdr->version ? hdr->version : SPT_VERSION;
    out[5] = hdr->type;
    ps_put_u16(out + 6, hdr->flags);
    ps_put_u32(out + 8, hdr->subflow_id);
    ps_put_u32(out + 12, hdr->key_generation);
    ps_put_u64(out + 16, hdr->record_sequence);
    ps_put_u64(out + 24, hdr->logical_offset);
    ps_put_u32(out + 32, hdr->plaintext_length);
    out[36] = hdr->protection;
    return 0;
}

int spt_header_decode(const uint8_t in[SPT_FRAME_HEADER_LEN], struct spt_header *hdr)
{
    if (!in || !hdr)
        return -1;
    if (ps_get_u32(in) != SPT_FRAME_MAGIC)
        return -1;
    if (in[4] != SPT_VERSION)
        return -1;
    if (in[36] != SPT_PROTECTION_CONFIDENTIAL && in[36] != SPT_PROTECTION_AUTHENTICATED &&
        in[36] != SPT_PROTECTION_TRANSPORT)
        return -1;
    if (in[37] != 0 || in[38] != 0 || in[39] != 0)
        return -1;
    memset(hdr, 0, sizeof(*hdr));
    hdr->version = in[4];
    hdr->type = in[5];
    hdr->protection = in[36];
    hdr->flags = ps_get_u16(in + 6);
    hdr->subflow_id = ps_get_u32(in + 8);
    hdr->key_generation = ps_get_u32(in + 12);
    hdr->record_sequence = ps_get_u64(in + 16);
    hdr->logical_offset = ps_get_u64(in + 24);
    hdr->plaintext_length = ps_get_u32(in + 32);
    if (hdr->plaintext_length > SPT_MAX_PLAIN)
        return -1;
    return 0;
}

int spt_ctrl_encode(uint8_t *out, size_t cap, uint16_t type,
                    const uint8_t *body, size_t body_len, size_t *written)
{
    if (!out || (body_len > 0 && !body))
        return -1;
    if (body_len > SPT_MAX_CTRL_BODY)
        return -1;
    size_t total = 8u + body_len;
    if (cap < total)
        return -1;
    ps_put_u32(out, (uint32_t)(4u + body_len));
    ps_put_u16(out + 4, type);
    ps_put_u16(out + 6, 0);
    if (body_len)
        memcpy(out + 8, body, body_len);
    if (written)
        *written = total;
    return 0;
}

int spt_ctrl_peek(const uint8_t *in, size_t len, uint16_t *type,
                  const uint8_t **body, size_t *body_len, size_t *consumed)
{
    if (!in || len < 8)
        return 1;
    uint32_t payload = ps_get_u32(in);
    if (payload < 4 || payload > 4u + SPT_MAX_CTRL_BODY)
        return -1;
    size_t total = 4u + (size_t)payload;
    if (len < total)
        return 1;
    if (ps_get_u16(in + 6) != 0)
        return -1;
    if (type)
        *type = ps_get_u16(in + 4);
    if (body)
        *body = in + 8;
    if (body_len)
        *body_len = (size_t)payload - 4u;
    if (consumed)
        *consumed = total;
    return 0;
}

int spt_client_hello_encode(uint8_t out[SPT_CLIENT_HELLO_LEN],
                            const struct spt_client_hello *msg)
{
    if (!out || !msg)
        return -1;
    memset(out, 0, SPT_CLIENT_HELLO_LEN);
    out[0] = SPT_PROTO_MAJOR;
    out[1] = SPT_PROTO_MINOR;
    ps_put_u16(out + 2, msg->aead);
    ps_put_u32(out + 4, msg->min_sockets);
    ps_put_u32(out + 8, msg->max_sockets);
    ps_put_u32(out + 12, msg->initial_sockets);
    ps_put_u32(out + 16, msg->frame_size);
    ps_put_u64(out + 20, msg->recv_window);
    ps_put_u32(out + 28, msg->flags);
    memcpy(out + 32, msg->client_random, SPT_RANDOM_LEN);
    return 0;
}

int spt_client_hello_decode(const uint8_t in[SPT_CLIENT_HELLO_LEN],
                            struct spt_client_hello *msg)
{
    if (!in || !msg)
        return -1;
    if (in[0] != SPT_PROTO_MAJOR || in[1] != SPT_PROTO_MINOR)
        return -1;
    memset(msg, 0, sizeof(*msg));
    msg->aead = ps_get_u16(in + 2);
    msg->min_sockets = ps_get_u32(in + 4);
    msg->max_sockets = ps_get_u32(in + 8);
    msg->initial_sockets = ps_get_u32(in + 12);
    msg->frame_size = ps_get_u32(in + 16);
    msg->recv_window = ps_get_u64(in + 20);
    msg->flags = ps_get_u32(in + 28);
    memcpy(msg->client_random, in + 32, SPT_RANDOM_LEN);
    return 0;
}

int spt_server_hello_encode(uint8_t out[SPT_SERVER_HELLO_LEN],
                            const struct spt_server_hello *msg)
{
    if (!out || !msg)
        return -1;
    memset(out, 0, SPT_SERVER_HELLO_LEN);
    out[0] = SPT_PROTO_MAJOR;
    out[1] = SPT_PROTO_MINOR;
    ps_put_u16(out + 2, msg->aead);
    ps_put_u32(out + 4, msg->initial_sockets);
    ps_put_u32(out + 8, msg->max_sockets);
    ps_put_u32(out + 12, msg->frame_size);
    ps_put_u64(out + 16, msg->recv_window);
    ps_put_u16(out + 24, msg->data_port);
    memcpy(out + 28, msg->server_random, SPT_RANDOM_LEN);
    memcpy(out + 60, msg->session_id, SPT_SESSION_ID_LEN);
    return 0;
}

int spt_server_hello_decode(const uint8_t in[SPT_SERVER_HELLO_LEN],
                            struct spt_server_hello *msg)
{
    if (!in || !msg)
        return -1;
    if (in[0] != SPT_PROTO_MAJOR || in[1] != SPT_PROTO_MINOR)
        return -1;
    if (ps_get_u16(in + 26) != 0)
        return -1;
    memset(msg, 0, sizeof(*msg));
    msg->aead = ps_get_u16(in + 2);
    msg->initial_sockets = ps_get_u32(in + 4);
    msg->max_sockets = ps_get_u32(in + 8);
    msg->frame_size = ps_get_u32(in + 12);
    msg->recv_window = ps_get_u64(in + 16);
    msg->data_port = ps_get_u16(in + 24);
    memcpy(msg->server_random, in + 28, SPT_RANDOM_LEN);
    memcpy(msg->session_id, in + 60, SPT_SESSION_ID_LEN);
    return 0;
}

int spt_subflow_hello_encode(uint8_t out[SPT_SUBFLOW_HELLO_LEN],
                             const struct spt_subflow_hello *msg)
{
    if (!out || !msg)
        return -1;
    ps_put_u32(out, msg->subflow_id);
    ps_put_u32(out + 4, msg->key_generation);
    memcpy(out + 8, msg->nonce, SPT_NONCE_LEN);
    return 0;
}

int spt_subflow_hello_decode(const uint8_t in[SPT_SUBFLOW_HELLO_LEN],
                             struct spt_subflow_hello *msg)
{
    if (!in || !msg)
        return -1;
    msg->subflow_id = ps_get_u32(in);
    msg->key_generation = ps_get_u32(in + 4);
    memcpy(msg->nonce, in + 8, SPT_NONCE_LEN);
    return 0;
}

int spt_preface_encode(uint8_t out[SPT_PREFACE_LEN], uint32_t subflow_id,
                       const uint8_t session_id[SPT_SESSION_ID_LEN])
{
    if (!out || !session_id)
        return -1;
    memset(out, 0, SPT_PREFACE_LEN);
    ps_put_u32(out, SPT_PREFACE_MAGIC);
    out[4] = SPT_VERSION;
    ps_put_u32(out + 8, subflow_id);
    memcpy(out + 12, session_id, SPT_SESSION_ID_LEN);
    return 0;
}

int spt_preface_decode(const uint8_t in[SPT_PREFACE_LEN], uint32_t *subflow_id,
                       uint8_t session_id[SPT_SESSION_ID_LEN])
{
    if (!in || !subflow_id || !session_id)
        return -1;
    if (ps_get_u32(in) != SPT_PREFACE_MAGIC || in[4] != SPT_VERSION)
        return -1;
    if (in[5] != 0 || in[6] != 0 || in[7] != 0)
        return -1;
    *subflow_id = ps_get_u32(in + 8);
    memcpy(session_id, in + 12, SPT_SESSION_ID_LEN);
    return 0;
}

int spt_quic_join_context(uint8_t out[SPT_QUIC_JOIN_CONTEXT_LEN], uint32_t lane_id,
                          const uint8_t client_nonce[SPT_NONCE_LEN],
                          const uint8_t server_nonce[SPT_NONCE_LEN],
                          const uint8_t session_id[SPT_SESSION_ID_LEN],
                          const uint8_t hello_hash[SPT_HASH_LEN])
{
    if (!out || !client_nonce || !server_nonce || !session_id || !hello_hash)
        return -1;
    ps_put_u32(out, lane_id);
    memcpy(out + 4, client_nonce, SPT_NONCE_LEN);
    memcpy(out + 4 + SPT_NONCE_LEN, server_nonce, SPT_NONCE_LEN);
    memcpy(out + 4 + SPT_NONCE_LEN + SPT_NONCE_LEN, session_id, SPT_SESSION_ID_LEN);
    memcpy(out + 4 + SPT_NONCE_LEN + SPT_NONCE_LEN + SPT_SESSION_ID_LEN, hello_hash, SPT_HASH_LEN);
    return 0;
}

int spt_join_encode(uint8_t out[SPT_JOIN_PLAIN_LEN], const struct spt_join_plain *msg)
{
    if (!out || !msg)
        return -1;
    memset(out, 0, SPT_JOIN_PLAIN_LEN);
    out[0] = SPT_VERSION;
    out[1] = msg->role;
    ps_put_u32(out + 4, msg->subflow_id);
    ps_put_u32(out + 8, msg->key_generation);
    memcpy(out + 12, msg->session_id, SPT_SESSION_ID_LEN);
    memcpy(out + 44, msg->client_nonce, SPT_NONCE_LEN);
    memcpy(out + 76, msg->server_nonce, SPT_NONCE_LEN);
    memcpy(out + 108, msg->hello_hash, SPT_HASH_LEN);
    return 0;
}

int spt_join_decode(const uint8_t in[SPT_JOIN_PLAIN_LEN], struct spt_join_plain *msg)
{
    if (!in || !msg)
        return -1;
    if (in[0] != SPT_VERSION)
        return -1;
    if (ps_get_u16(in + 2) != 0)
        return -1;
    memset(msg, 0, sizeof(*msg));
    msg->role = in[1];
    msg->subflow_id = ps_get_u32(in + 4);
    msg->key_generation = ps_get_u32(in + 8);
    memcpy(msg->session_id, in + 12, SPT_SESSION_ID_LEN);
    memcpy(msg->client_nonce, in + 44, SPT_NONCE_LEN);
    memcpy(msg->server_nonce, in + 76, SPT_NONCE_LEN);
    memcpy(msg->hello_hash, in + 108, SPT_HASH_LEN);
    return 0;
}

int spt_transport_offer_encode(uint8_t out[SPT_TRANSPORT_OFFER_LEN],
                               const struct spt_transport_offer *msg)
{
    if (!out || !msg)
        return -1;
    memset(out, 0, SPT_TRANSPORT_OFFER_LEN);
    out[0] = msg->preference;
    out[1] = msg->fallback ? 1 : 0;
    ps_put_u32(out + 4, msg->initial_lanes);
    ps_put_u32(out + 8, msg->max_lanes);
    ps_put_u32(out + 12, msg->send_depth);
    ps_put_u32(out + 16, msg->recv_depth);
    ps_put_u32(out + 20, msg->max_message);
    return 0;
}

int spt_transport_offer_decode(const uint8_t in[SPT_TRANSPORT_OFFER_LEN],
                               struct spt_transport_offer *msg)
{
    if (!in || !msg)
        return -1;
    if (ps_get_u16(in + 2) != 0)
        return -1;
    if (in[0] != SPT_TRANSPORT_TCP && in[0] != SPT_TRANSPORT_RDMA_RC &&
        in[0] != SPT_TRANSPORT_QUIC)
        return -1;
    memset(msg, 0, sizeof(*msg));
    msg->preference = in[0];
    msg->fallback = in[1] ? 1 : 0;
    if (in[1] != 0 && in[1] != 1)
        return -1;
    msg->initial_lanes = ps_get_u32(in + 4);
    msg->max_lanes = ps_get_u32(in + 8);
    msg->send_depth = ps_get_u32(in + 12);
    msg->recv_depth = ps_get_u32(in + 16);
    msg->max_message = ps_get_u32(in + 20);
    if (msg->initial_lanes < 1 || msg->max_lanes < msg->initial_lanes)
        return -1;
    if (msg->max_message < SPT_FRAME_HEADER_LEN + SPT_TAG_LEN || msg->max_message > SPT_MAX_FRAME)
        return -1;
    return 0;
}

int spt_transport_select_encode(uint8_t out[SPT_TRANSPORT_SELECT_LEN],
                                const struct spt_transport_select *msg)
{
    if (!out || !msg)
        return -1;
    memset(out, 0, SPT_TRANSPORT_SELECT_LEN);
    out[0] = msg->transport;
    ps_put_u16(out + 2, msg->rdma_port);
    ps_put_u32(out + 4, msg->lanes);
    ps_put_u32(out + 8, msg->send_depth);
    ps_put_u32(out + 12, msg->recv_depth);
    return 0;
}

int spt_transport_select_decode(const uint8_t in[SPT_TRANSPORT_SELECT_LEN],
                                struct spt_transport_select *msg)
{
    if (!in || !msg)
        return -1;
    if (in[1] != 0)
        return -1;
    if (in[0] != SPT_TRANSPORT_TCP && in[0] != SPT_TRANSPORT_RDMA_RC &&
        in[0] != SPT_TRANSPORT_QUIC)
        return -1;
    memset(msg, 0, sizeof(*msg));
    msg->transport = in[0];
    msg->rdma_port = ps_get_u16(in + 2);
    msg->lanes = ps_get_u32(in + 4);
    msg->send_depth = ps_get_u32(in + 8);
    msg->recv_depth = ps_get_u32(in + 12);
    if (msg->lanes < 1 || msg->lanes > 64)
        return -1;
    if (msg->transport == SPT_TRANSPORT_RDMA_RC &&
        (msg->lanes > 16 || msg->rdma_port == 0 || msg->send_depth < 2 || msg->recv_depth < 4 ||
         msg->send_depth > 256 || msg->recv_depth > 256))
        return -1;
    if (msg->transport == SPT_TRANSPORT_QUIC &&
        (msg->lanes > 16 || msg->rdma_port == 0 || msg->send_depth != 0 || msg->recv_depth != 0))
        return -1;
    return 0;
}
