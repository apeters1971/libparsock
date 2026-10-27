# [SPT Extension RFC] Parallel QUIC Transport Backend for libparsock

**Project:** libparsock
**Protocol:** Secure Parallel Transport (SPT)
**Extension:** QUIC Transport Backend
**Status:** Userspace prototype. One bidirectional stream per connection. Fixed lane count.
**Library:** ngtcp2 with `libngtcp2_crypto_ossl` (OpenSSL 3 TLS 1.3)
**Security:** TLS 1.3 control plane stays on TCP. QUIC carries the data plane and supplies encryption. SPT framing is retained. A second SPT AEAD is not applied.
**Relationship to core RFC:** Optional extension. The default transport stays TCP. Automatic transport selection does not offer QUIC.

The TCP wire format is [spt-0.1.md](spt-0.1.md). The RDMA extension is [spt-rdma.md](spt-rdma.md). This tree implements the QUIC data plane when libngtcp2 and libngtcp2_crypto_ossl are present. Kernel clients, `sptd`, native XRootD, cross-socket retransmission, io_uring, mixed TCP/RDMA/QUIC lanes, and adaptive lane counts are out of scope. Section 8 is the wire format used by this implementation.

---

## 1. Executive Summary

SPT already presents one reliable, ordered, bidirectional byte stream over several independent lanes. TCP lanes are sockets. RDMA lanes are reliable-connected queue pairs. This extension adds QUIC lanes: each lane is its own QUIC connection, and each connection carries one client-opened bidirectional stream.

The application still sees one stream, one session, and the same send and receive calls. QUIC replaces the custom AEAD on those lanes. The SPT record header stays, so reassembly, flow control, and subflow identity do not move into a private QUIC framing scheme.

A fixed number of connections is negotiated, at most 16. The client uses one connected UDP socket per lane, so each lane has its own 4-tuple. The server listens on one UDP socket and demultiplexes packets by connection ID.

## 2. Why a separate connection per lane

One QUIC connection can open many streams, but those streams share one congestion controller, one loss recovery context, and one UDP 4-tuple. SPT lanes are independent paths that the session scheduler can fill in parallel. Giving each lane its own connection keeps that independence:

- Loss on one lane does not stall the congestion window of the others.
- The host can spread the sockets across queues later (`SO_REUSEPORT` and RSS are not part of this prototype).
- A failed lane is one connection, not one stream inside a connection that still has to drain the others.

The cost is a handshake per lane and a join check per lane. The first prototype accepts that cost. Four connections is the configuration exercised by the transfer test.

## 3. Encryption

QUIC already authenticates and encrypts every packet with TLS 1.3. Wrapping those packets in the SPT AEAD would encrypt twice and spend the CPU the transport was meant to save. Lanes that use this backend mark records with protection `SPT_PROTECTION_TRANSPORT` (value 2). The on-wire record is the 40-byte SPT header followed by the plaintext. There is no SPT authentication tag on ordinary records.

`spt_protection_accepts` does not treat transport protection as satisfying a confidentiality minimum. The session accepts it only on a lane that was negotiated as QUIC. Callers still pass confidential protection into the enqueue path. The session rewrites that to transport protection when the lane is QUIC.

SPT rekey does not rotate keys on a QUIC lane. QUIC updates its own traffic keys. `ps_rekey` on a QUIC session returns an error.

## 4. Binding a QUIC connection to the SPT session

A QUIC handshake proves possession of the certificate. It does not, by itself, prove that the connection belongs to the SPT session that negotiated the lane. Connection IDs are not authentication tokens.

After the QUIC handshake, each lane exchanges the existing JOIN / JOIN_ACK body (140 bytes). On a QUIC lane that body is followed by a 16-byte tag:

```text
tag = truncate_16(HMAC-SHA256(exporter, header || join_body))
```

The HMAC key is 32 bytes from `SSL_export_keying_material` on that connection's TLS session, after the handshake has finished. The label is:

```text
EXPORTER-libparsock-spt-quic/0.1
```

The exporter context is 132 bytes and is the same on both peers. Role is not part of it. Role is carried in the join body.

```text
u32be(lane_id) || client_nonce(32) || server_nonce(32) || session_id(32) || hello_hash(32)
```

The tag covers the encoded 40-byte header, so it is computed inside the session once the record sequence and length exist. A caller passes the 140-byte join body.

The server buffers stream bytes on an unbound connection until a full JOIN is present. A bad tag, a JOIN for a lane that is not waiting, or a handshake that never becomes a lane drops that QUIC connection and does not fail the SPT session. A failure of a lane that has already been bound fails the session.

The client sends JOIN only after the handshake is complete and the bidirectional stream exists. The server's first record on that lane is JOIN. The client's first record is JOIN_ACK.

## 5. Connection model

| Role | UDP | QUIC | Stream |
|---|---|---|---|
| Client | One connected socket per lane, ephemeral source port | `ngtcp2_conn_client_new`, QUIC v1, 18-byte connection IDs | Client opens one bidirectional stream (id 0) |
| Server | One socket bound to port 0, port announced in TRANSPORT_SELECT | `ngtcp2_accept` then `ngtcp2_conn_server_new` | Server does not open a stream |

Active migration is disabled. The congestion controller is Cubic. The stream and connection flow-control windows are 1 MiB. The session extends both windows when it consumes stream bytes, and it does that outside ngtcp2 callbacks. Handshake timeout is 15 seconds. Idle timeout is 120 seconds.

ALPN is mandatory. The identifier on the wire is the 4 bytes `spt` with a length prefix of 3. The server selects it. A connection that does not offer it does not become a lane.

The library does not own the event loop. The poll thread, or an external poller, watches the UDP sockets and calls `ps_session_quic_service`. That call reads datagrams, runs timers, pulls stream bytes into the SPT parser, and writes queued records. Timers use `ngtcp2_conn_get_expiry`. Only the session's first I/O lane polls QUIC sockets, matching the RDMA completion queue.

## 6. Negotiation

QUIC is explicit. `PS_TRANSPORT_AUTO` keeps the existing RDMA-or-TCP path and does not offer QUIC. `PS_TRANSPORT_QUIC` offers QUIC. `allow_tcp_fallback` still authorizes a TCP selection. The C++ `options::transport(quic)` clears fallback, as it does for RDMA. A test that requires QUIC sets fallback to 0 so a failed handshake cannot succeed as TCP.

Lane count reuses `initial_sockets` / `max_sockets`. There is no separate public QUIC options struct. The negotiated count is fixed for the session and is at most 16.

The server listens before it sends TRANSPORT_SELECT. The select message reuses the existing 16-bit port field (the RDMA CM port on an RDMA selection) as the QUIC UDP port. Send depth and receive depth are 0. A QUIC select with a zero port or a non-zero depth is rejected.

The client connects each lane after SUBFLOW_ACCEPT, to the control peer's address at that UDP port. SUBFLOW_OPEN and SUBFLOW_ACCEPT are unchanged and still carry the lane nonces used in the join context.

## 7. What this prototype does not do

- It does not open more than one stream on a connection.
- It does not scale the lane count after the session is open.
- It does not mix QUIC lanes with TCP or RDMA lanes in one session.
- It does not use `SO_REUSEPORT` or RSS to steer server packets.
- It does not retransmit SPT records across lanes. QUIC recovers loss inside the lane. The session still delivers bytes in order across lanes through the existing reassembly buffer.
- It does not apply the SPT AEAD, and it does not accept transport protection on a TCP or RDMA lane.

## 8. Wire Format Implemented Here

Integers are big-endian. Control messages travel on the TLS connection. A session uses one data-plane transport.

`TRANSPORT_OFFER` (type 15) is 24 bytes. A QUIC client sends it after the hellos:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | preference: 3 QUIC |
| 1 | 1 | fallback: 1 if TCP is authorized |
| 2 | 2 | reserved, must be 0 |
| 4 | 4 | initial lanes, 1..16 |
| 8 | 4 | maximum lanes, at least the initial count, at most 16 |
| 12 | 4 | send depth, 0 |
| 16 | 4 | receive depth, 0 |
| 20 | 4 | maximum message size. This build advertises the TCP AEAD frame size so an existing minimum-size check still passes |

`TRANSPORT_SELECT` (type 16) is 16 bytes, server to client:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | 3 for QUIC |
| 1 | 1 | reserved, must be 0 |
| 2 | 2 | QUIC UDP port, never 0 |
| 4 | 4 | lanes, 1..16 |
| 8 | 4 | send depth, 0 |
| 12 | 4 | receive depth, 0 |

Transport identifiers in this tree are TCP = 1, RDMA RC = 2, QUIC = 3.

QUIC lanes then use `SUBFLOW_OPEN` and `SUBFLOW_ACCEPT`. There is no cleartext preface on the QUIC stream. The first record is JOIN (server receives it) or JOIN_ACK (client receives it).

A data record on a QUIC lane:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 40 | SPT frame header, protection = 2, key generation = 0 |
| 40 | plaintext_length | record body |

JOIN and JOIN_ACK use the same header. `plaintext_length` is 156: the 140-byte join body and the 16-byte exporter tag. The tag is not present on other record types.

The listener and the tests use IPv4. The socket helpers also accept IPv6. `ps_options.transport = PS_TRANSPORT_QUIC` selects this backend. `ps_quic_supported` is 1 when the library was built with ngtcp2.

## References

- ngtcp2 and ngtcp2_crypto_ossl
- QUIC: RFC 9000. QUIC-TLS: RFC 9001
- TLS exporters: RFC 8446, section 7.5
- SPT/0.1: [spt-0.1.md](spt-0.1.md)
