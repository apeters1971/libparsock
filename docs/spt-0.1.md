# SPT/0.1 experimental wire specification

This document matches the userspace implementation in this repository. Integers are big-endian. Nothing on the wire is a host C structure, a pointer, or a CPU endianness flag. The version byte is `1`. Protocol negotiation numbers are major `0`, minor `1`.

SPT/0.1 is a research protocol. It is not wire-compatible with HTTPS.

## Planes

One TLS 1.3 connection is the control plane. It stays open for the session and carries only length-prefixed SPT control messages as TLS application data. OpenSSL is used unmodified. `SSL_export_keying_material` is called only after both hello bodies exist.

Each data socket carries a cleartext preface and then AEAD records. Data sockets do not speak TLS.

The client opens every data TCP connection. The server advertises an ephemeral data port in `SERVER_HELLO`. Failure of any data socket fails the whole session. There is no cross-socket retransmission in 0.1.

## Control messages

A control message is:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | payload length, including the following type and flags |
| 4 | 2 | type |
| 6 | 2 | flags, must be 0 |
| 8 | payload−4 | body |

The on-wire size is `8 + body`. The maximum body is 65532 bytes. A peer that does not yet have 8 bytes, or that does not yet have the full payload, waits. A payload length below 4, a payload above the maximum, or nonzero flags is an error.

| Type | Name | Body |
|---:|---|---|
| 1 | CLIENT_HELLO | 64 |
| 2 | SERVER_HELLO | 92 |
| 3 | SUBFLOW_OPEN | 40 |
| 4 | SUBFLOW_ACCEPT | 40 |
| 5 | SUBFLOW_REJECT | 8: subflow id, error code |
| 6 | WINDOW_UPDATE | 8: absolute receive limit |
| 7 | SUBFLOW_DRAIN | 4: subflow id |
| 8 | SUBFLOW_RETIRED | 4: subflow id |
| 9 | CLOSE | 4: error code |
| 10 | ERROR | 4: error code |
| 11 | SCALE_REQUEST | 4: desired socket count |
| 12 | KEY_UPDATE | 8: subflow id, generation |
| 13 | KEY_UPDATE_ACK | 8: subflow id, generation |

### CLIENT_HELLO

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | major = 0 |
| 1 | 1 | minor = 1 |
| 2 | 2 | AEAD id |
| 4 | 4 | minimum sockets |
| 8 | 4 | maximum sockets |
| 12 | 4 | initial sockets |
| 16 | 4 | frame size |
| 20 | 8 | receive window |
| 28 | 4 | flags (bit 0 is set and ignored) |
| 32 | 32 | client random |

### SERVER_HELLO

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | major = 0 |
| 1 | 1 | minor = 1 |
| 2 | 2 | AEAD id |
| 4 | 4 | accepted initial sockets |
| 8 | 4 | maximum sockets |
| 12 | 4 | frame size |
| 16 | 8 | receive window |
| 24 | 2 | data port |
| 26 | 2 | reserved, must be 0 |
| 28 | 32 | server random |
| 60 | 32 | session id |

The data port must be nonzero. Frame size is clamped to the range `[1024, 262144]`.

### Subflow hello

`SUBFLOW_OPEN` and `SUBFLOW_ACCEPT` share one body:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | subflow id |
| 4 | 4 | key generation |
| 8 | 32 | nonce |

The client allocates subflow ids from 0 upward and never reuses them. At most 64 subflows exist in a session. The server answers `SUBFLOW_OPEN` with `SUBFLOW_ACCEPT` and a fresh server nonce.

## Key schedule

Exporter label, without a trailing NUL:

```text
EXPORTER-libparsock-spt/0.1
```

Exporter context, 96 bytes:

```text
client_random || server_random || session_id
```

These randoms are the SPT hello randoms, not the TLS handshake randoms. The exporter output is 32 bytes and is the SPT root.

HKDF-SHA256 (RFC 5869) extract-and-expand:

- salt: ASCII `spt-hkdf-salt-v1` with no NUL
- IKM: the 32-byte root
- output: 44 bytes, key (32) then static IV (12)

HKDF info, with no NULs:

```text
"spt-aead-v1" (11) || u8 direction || u32 subflow_id || u32 generation
    || u16 aead || client_nonce (32) || server_nonce (32) || session_id (32)
```

Direction 0 is client-to-server. Direction 1 is server-to-client. Keys are independent per direction, subflow, and generation. The last two generations are retained.

AEAD ids:

| Id | Algorithm |
|---:|---|
| 1 | AES-256-GCM |
| 2 | ChaCha20-Poly1305 |

The authentication tag is 16 bytes. The nonce is 12 bytes:

```text
nonce = static_iv XOR encode96(record_sequence)
```

`encode96` is 4 zero bytes followed by the sequence as a big-endian `u64`. Nonce reuse under one key is forbidden. A direction on a subflow and generation may seal at most `2^20` records, then that side sends `KEY_UPDATE` for the next generation. Sequence 0 of generation 0 is `JOIN` from the client and `JOIN_ACK` from the server. Later generations may use sequence 0 for data. The sender switches to a new generation only after it has announced the generation and has seen the peer's announcement. A receiver installs the next generation when it sees a record with `generation + 1` and sequence 0.

`hello_hash` is SHA-256 of `client_hello_body || server_hello_body`, the raw hello bodies, not the control envelopes.

## Data preface

Each client data socket sends 44 cleartext bytes before any AEAD record:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `SPTJ` (`0x5350544A`) |
| 4 | 1 | version = 1 |
| 5 | 3 | reserved, must be 0 |
| 8 | 4 | subflow id |
| 12 | 32 | session id |

The client nonce is not in the preface. It is inside the encrypted `JOIN`. The server reads exactly 44 bytes, finds the session, and then reads `JOIN`.

## Records

A record is a 40-byte header, ciphertext of the plaintext, and a 16-byte tag. The header is AEAD associated data. The maximum plaintext is 256 KiB. The default plaintext size is 64 KiB.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `SPT1` (`0x53505431`) |
| 4 | 1 | version = 1 |
| 5 | 1 | type |
| 6 | 2 | flags |
| 8 | 4 | subflow id |
| 12 | 4 | key generation |
| 16 | 8 | record sequence |
| 24 | 8 | logical offset |
| 32 | 4 | plaintext length |
| 36 | 4 | reserved, must be 0 |

Unknown flag bits are rejected. The only defined flag is `FIN` (`0x0001`).

| Type | Name | Rules |
|---:|---|---|
| 1 | DATA | plaintext length > 0, no FIN, logical offset is the first byte |
| 2 | JOIN | 140-byte plaintext, generation 0, sequence 0, client role |
| 3 | JOIN_ACK | 140-byte plaintext, generation 0, sequence 0, server role |
| 4 | SUBFLOW_END | empty plaintext |
| 5 | EOS | empty plaintext, FIN set, logical offset is the end of that direction |

`JOIN` plaintext:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version = 1 |
| 1 | 1 | role (1 client, 2 server) |
| 2 | 2 | reserved, must be 0 |
| 4 | 4 | subflow id |
| 8 | 4 | key generation |
| 12 | 32 | session id |
| 44 | 32 | client nonce |
| 76 | 32 | server nonce |
| 108 | 32 | hello hash |

The server checks the client role, the nonces, the session id, and the hello hash, then sends `JOIN_ACK` with the server role. The client checks that the ack role is the server.

Within one direction, subflow, and generation, `record_sequence` increases by 1. TCP preserves order on a socket, so the receiver rejects a sequence other than the next expected value, except the first record of the next generation, which must be sequence 0.

## Flow control

Each hello advertises an absolute receive limit. The sender may assign logical bytes while `offset + length` does not pass the peer limit. `WINDOW_UPDATE` carries a new absolute limit and must not move backwards. `EOS` is not limited by the window.

The receiver buffers out-of-order plaintext only inside `deliver + receive_window`. A record past that window fails the session. Identical overlapping bytes are ignored. Conflicting overlap fails the session.

## Subflow retirement

`SUBFLOW_DRAIN` stops new data on that subflow. Each side sends `SUBFLOW_END` after its output queue is empty. The subflow is retired when both ends have been seen. `SUBFLOW_RETIRED` is informational. At least one subflow remains. Retired ids are not reused.

## Error codes

| Code | Name |
|---:|---|
| 0 | OK |
| 1 | protocol |
| 2 | authentication |
| 3 | cryptographic |
| 4 | flow control |
| 5 | internal |
| 6 | unsupported |
| 7 | closed |
| 8 | usage limit |

## Interoperability tests

An independent implementation has to reproduce:

- header, control, preface, hello, and join codecs
- HKDF-SHA256 output for the info string above, checked against HMAC-SHA256 rather than against this tree's `EVP_KDF` call
- AES-256-GCM and ChaCha20-Poly1305 seals, including empty plaintext, and rejection of a modified tag
- nonce `static_iv XOR encode96(sequence)`
