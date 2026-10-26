#include "spt_wire.h"

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
    struct spt_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = SPT_VERSION;
    hdr.type = SPT_REC_DATA;
    hdr.flags = 0;
    hdr.subflow_id = 0x01020304u;
    hdr.key_generation = 7;
    hdr.record_sequence = 0x1122334455667788ull;
    hdr.logical_offset = 0xaabbccddeeff0011ull;
    hdr.plaintext_length = 64;
    uint8_t raw[SPT_FRAME_HEADER_LEN];
    expect(spt_header_encode(raw, &hdr) == 0, "encode header");
    expect(raw[0] == 'S' && raw[1] == 'P' && raw[2] == 'T' && raw[3] == '1', "magic");
    expect(spt_frame_wire_len(64) == 40u + 64u + 16u, "wire length");
    struct spt_header back;
    expect(spt_header_decode(raw, &back) == 0, "decode header");
    expect(back.subflow_id == hdr.subflow_id && back.record_sequence == hdr.record_sequence &&
               back.logical_offset == hdr.logical_offset && back.plaintext_length == 64,
           "header fields");
    raw[0] ^= 1;
    expect(spt_header_decode(raw, &back) != 0, "bad magic");
    raw[0] ^= 1;
    raw[4] = 9;
    expect(spt_header_decode(raw, &back) != 0, "bad version");
    raw[4] = SPT_VERSION;
    expect(back.protection == SPT_PROTECTION_CONFIDENTIAL, "default profile");
    raw[36] = SPT_PROTECTION_AUTHENTICATED;
    expect(spt_header_decode(raw, &back) == 0, "authenticated profile");
    expect(back.protection == SPT_PROTECTION_AUTHENTICATED, "profile field");
    raw[37] = 1;
    expect(spt_header_decode(raw, &back) != 0, "reserved tail");
    raw[37] = 0;
    raw[36] = 2;
    expect(spt_header_decode(raw, &back) != 0, "unknown profile");
    raw[36] = 0;
    expect(spt_protection_accepts(SPT_PROTECTION_CONFIDENTIAL, SPT_PROTECTION_CONFIDENTIAL),
           "floor confidential");
    expect(!spt_protection_accepts(SPT_PROTECTION_CONFIDENTIAL, SPT_PROTECTION_AUTHENTICATED),
           "reject downgrade");
    expect(spt_protection_accepts(SPT_PROTECTION_AUTHENTICATED, SPT_PROTECTION_CONFIDENTIAL),
           "confidential exceeds floor");
    expect(spt_protection_accepts(SPT_PROTECTION_AUTHENTICATED, SPT_PROTECTION_AUTHENTICATED),
           "authenticated floor");
    expect(!spt_protection_accepts(9, SPT_PROTECTION_CONFIDENTIAL), "unknown floor");
    hdr.plaintext_length = SPT_MAX_PLAIN + 1;
    expect(spt_header_encode(raw, &hdr) == 0, "encode oversize");
    expect(spt_header_decode(raw, &back) != 0, "reject oversize");

    uint8_t body[4] = {1, 2, 3, 4};
    uint8_t ctrl[32];
    size_t written = 0;
    expect(spt_ctrl_encode(ctrl, sizeof(ctrl), SPT_CTRL_CLOSE, body, 4, &written) == 0, "ctrl encode");
    expect(written == 12, "ctrl size");
    uint16_t type = 0;
    const uint8_t *got = NULL;
    size_t blen = 0;
    size_t consumed = 0;
    expect(spt_ctrl_peek(ctrl, 7, &type, &got, &blen, &consumed) == 1, "ctrl short");
    expect(spt_ctrl_peek(ctrl, written, &type, &got, &blen, &consumed) == 0, "ctrl peek");
    expect(type == SPT_CTRL_CLOSE && blen == 4 && consumed == 12 && memcmp(got, body, 4) == 0,
           "ctrl body");
    ctrl[7] = 1;
    expect(spt_ctrl_peek(ctrl, written, &type, &got, &blen, &consumed) != 0, "ctrl flags");

    struct spt_client_hello ch;
    memset(&ch, 0, sizeof(ch));
    ch.aead = SPT_AEAD_AES_256_GCM;
    ch.min_sockets = 1;
    ch.max_sockets = 4;
    ch.initial_sockets = 4;
    ch.frame_size = 65536;
    ch.recv_window = 8ull << 20;
    ch.flags = 1;
    memset(ch.client_random, 0x11, SPT_RANDOM_LEN);
    uint8_t chb[SPT_CLIENT_HELLO_LEN];
    expect(spt_client_hello_encode(chb, &ch) == 0, "ch encode");
    struct spt_client_hello ch2;
    expect(spt_client_hello_decode(chb, &ch2) == 0, "ch decode");
    expect(ch2.aead == ch.aead && ch2.recv_window == ch.recv_window &&
               memcmp(ch2.client_random, ch.client_random, 32) == 0,
           "ch fields");

    struct spt_server_hello sh;
    memset(&sh, 0, sizeof(sh));
    sh.aead = SPT_AEAD_CHACHA20_POLY1305;
    sh.initial_sockets = 2;
    sh.max_sockets = 8;
    sh.frame_size = 65536;
    sh.recv_window = 1024;
    sh.data_port = 5201;
    memset(sh.server_random, 0x22, 32);
    memset(sh.session_id, 0x33, 32);
    uint8_t shb[SPT_SERVER_HELLO_LEN];
    expect(spt_server_hello_encode(shb, &sh) == 0, "sh encode");
    struct spt_server_hello sh2;
    expect(spt_server_hello_decode(shb, &sh2) == 0, "sh decode");
    expect(sh2.data_port == 5201 && memcmp(sh2.session_id, sh.session_id, 32) == 0, "sh fields");
    shb[26] = 1;
    expect(spt_server_hello_decode(shb, &sh2) != 0, "sh reserved");

    uint8_t sid[32];
    memset(sid, 0xab, sizeof(sid));
    uint8_t pref[SPT_PREFACE_LEN];
    expect(spt_preface_encode(pref, 3, sid) == 0, "preface");
    expect(pref[0] == 'S' && pref[1] == 'P' && pref[2] == 'T' && pref[3] == 'J', "preface magic");
    uint32_t sfid = 0;
    uint8_t sid2[32];
    expect(spt_preface_decode(pref, &sfid, sid2) == 0 && sfid == 3 && memcmp(sid, sid2, 32) == 0,
           "preface decode");

    struct spt_join_plain join;
    memset(&join, 0, sizeof(join));
    join.role = SPT_ROLE_SERVER;
    join.subflow_id = 3;
    join.key_generation = 0;
    memset(join.session_id, 1, 32);
    memset(join.client_nonce, 2, 32);
    memset(join.server_nonce, 3, 32);
    memset(join.hello_hash, 4, 32);
    uint8_t jb[SPT_JOIN_PLAIN_LEN];
    expect(spt_join_encode(jb, &join) == 0, "join encode");
    struct spt_join_plain join2;
    expect(spt_join_decode(jb, &join2) == 0, "join decode");
    expect(join2.role == SPT_ROLE_SERVER && join2.subflow_id == 3 &&
               memcmp(join2.hello_hash, join.hello_hash, 32) == 0,
           "join fields");

    if (fails) {
        fprintf(stderr, "%d frame checks failed\n", fails);
        return 1;
    }
    return 0;
}
