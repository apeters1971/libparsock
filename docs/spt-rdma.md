# [SPT Extension RFC] RDMA Transport Backend for libparsock

**Project:** libparsock
**Protocol:** Secure Parallel Transport (SPT)
**Extension:** RDMA Transport Backend
**Status:** RC SEND/RECV implemented; RDMA WRITE is research
**Target:** 100 / 200 / 400 / 800 GbE
**Initial implementation:** Linux userspace
**Initial RDMA transport:** Reliable Connected (RC), SEND/RECV
**Future transport:** RDMA WRITE
**Security:** TLS 1.3 control plane, SPT record protection
**Integration targets:** XRootD, HTTP, scientific data transfer, future kernel clients
**Relationship to core RFC:** Optional extension; not required for the initial TCP implementation

The TCP wire format is [spt-0.1.md](spt-0.1.md). This tree implements Reliable Connected SEND/RECV when librdmacm and libibverbs are present. The default transport stays TCP. RDMA WRITE, dynamic QP scaling, and the kernel backend are not implemented. Section 25 is the wire format used by this implementation.

---

## 1. Executive Summary

libparsock was originally conceived as a library that combines multiple TCP sockets into one reliable, ordered, secure logical byte stream.

Its architecture already separates the logical stream protocol from the I/O execution backend. This makes it possible to support RDMA without changing the application-facing abstraction.

This extension proposes adding RDMA as an alternative SPT data-plane transport.

The application continues to see:

- One logical ordered byte stream.
- One authenticated SPT session.
- A consistent send/receive interface.
- Configurable confidentiality and integrity policies.
- Transport-independent flow control and reassembly.

The transport backend determines whether data is carried over:

- Multiple conventional TCP sockets.
- One or more RDMA queue pairs.
- Future transport mechanisms.

**The primary goal of RDMA support is to reduce CPU overhead and memory movement, not necessarily to increase the number of parallel connections.**

The initial RDMA backend should use Reliable Connected (RC) SEND/RECV operations through `libibverbs`.

RDMA WRITE and more aggressive zero-copy optimizations are deferred to later research.

---

## 2. Motivation

At 400–800 GbE, traditional TCP processing can consume substantial CPU resources.

Even with parallel sockets, performance may be limited by:

- Kernel TCP processing.
- Socket buffer management.
- Memory copies.
- Cache contention.
- Crypto processing.
- Event-loop scheduling.
- NUMA traffic.

RDMA-capable NICs can move data directly between registered memory regions with comparatively low CPU involvement.

This makes RDMA a useful alternative to parallel TCP for large scientific transfers.

However, RDMA introduces its own complexities:

- Memory registration.
- Queue-pair management.
- Completion queues.
- Receive-buffer provisioning.
- Access permissions.
- Device and fabric requirements.
- Different failure semantics.

The SPT core should hide these details from applications.

---

## 3. Architectural Principle

**SPT is a logical stream protocol, not a TCP-specific protocol.**

TCP sockets and RDMA queue pairs are transport mechanisms used to move authenticated SPT records.

The application-visible abstraction remains unchanged.

### Proposed Architecture

```text
                 XRootD / HTTP / Application
                            |
                  SPT Logical Stream API
                            |
                +-----------+-----------+
                |       SPT Core        |
                |                       |
                | Logical offsets       |
                | Framing               |
                | Security policy       |
                | Record authentication |
                | Flow control          |
                | Ordered reassembly    |
                | Session management    |
                +-----------+-----------+
                            |
                  Transport Abstraction
                            |
            +---------------+---------------+
            |               |               |
       Parallel TCP        RDMA          Future
            |               |           transports
       epoll/io_uring   libibverbs
       TCP sockets      RC queue pairs
            |               |
       Linux TCP/IP     RDMA-capable NIC
            |               |
            +---------------+
                            |
                       Network fabric
```

The TLS control connection remains TCP-based for both transport types.

---

## 4. Transport-Neutral Lanes

The existing concept of a TCP *subflow* should be generalized internally to a **transport lane**.

A transport lane is an independently managed data-transfer path within an authenticated SPT session.

Examples:

```text
SPT session
    |
    +-- TCP lane 0
    +-- TCP lane 1
    +-- TCP lane 2
    +-- TCP lane 3
```

Or:

```text
SPT session
    |
    +-- RDMA RC QP lane 0
    +-- RDMA RC QP lane 1
```

A lane has:

- A unique identity.
- A transport type.
- Lifecycle state.
- Send/receive capabilities.
- Flow-control state.
- Security context.
- Completion handling.
- Performance telemetry.

The optimal lane count is transport-specific.

Multiple TCP sockets may improve RSS and CPU distribution.

A single RDMA QP may already provide sufficient throughput for some workloads.

The RDMA backend must not inherit TCP-specific socket-count heuristics.

---

## 5. Transport Capability Negotiation

The TLS 1.3 control connection negotiates available SPT transport types.

Candidate transport identifiers:

```c
typedef enum {
    SPT_TRANSPORT_TCP = 1,
    SPT_TRANSPORT_RDMA_RC = 2
} spt_transport_type_t;
```

Negotiated capabilities may include:

- Transport type.
- Maximum lane count.
- Maximum record size.
- Maximum outstanding operations.
- Receive credits.
- Supported protection profiles.
- Supported cryptographic algorithms.
- RDMA device capabilities.
- Memory registration constraints.

Transport negotiation must be authenticated and bound to the SPT session.

A peer must not silently switch transport types without authorization.

### Initial Negotiation Policy

For the first RDMA prototype:

1. Establish TLS control over TCP.
2. Authenticate both endpoints.
3. Negotiate SPT and RDMA capabilities.
4. Select RDMA RC SEND/RECV.
5. Establish authenticated RDMA lanes.
6. Begin SPT record transfer.

If RDMA is unavailable, fallback to TCP is permitted only when authorized by the negotiated session policy.

---

## 6. RDMA Connection Establishment

The initial implementation should use Linux RDMA userspace facilities.

Candidate libraries:

- `libibverbs`
- `librdmacm`

`librdmacm` may simplify connection establishment, while `libibverbs` provides direct control over RDMA resources.

### Required Resources

Each endpoint may need:

- RDMA device context.
- Protection domain.
- Completion queue.
- Queue pair.
- Registered memory regions.
- Posted receive buffers.
- Completion processing.
- Connection management state.

### Authenticated RDMA Lane Join

The TLS control connection authorizes each RDMA lane.

The join procedure must bind:

- SPT session identifier.
- RDMA lane identifier.
- Endpoint roles.
- Fresh nonces.
- Negotiated transport parameters.
- RDMA connection identity.
- Key generation.

The exact join transcript and authentication procedure must be defined in the SPT wire specification.

RDMA connection metadata must not be treated as sufficient authentication by itself.

---

## 7. Initial RDMA Transport: RC SEND/RECV

The first RDMA backend should use Reliable Connected queue pairs with SEND/RECV operations.

### Why SEND/RECV First?

SEND/RECV provides message-oriented communication that maps naturally onto SPT records.

It allows:

- Explicit record boundaries.
- Receiver-controlled buffer provisioning.
- Completion-based processing.
- Authentication before application delivery.
- Straightforward logical-offset reassembly.

### Send Path

```text
Application buffer
       |
SPT logical stream scheduler
       |
SPT record construction
       |
AEAD encryption or MAC
       |
Registered send buffer
       |
RDMA SEND work request
       |
NIC transmission
```

### Receive Path

```text
Posted registered receive buffer
       |
RDMA RECV completion
       |
SPT frame validation
       |
AEAD verification / decryption
       |
Logical offset reassembly
       |
Application delivery
```

The receiver must post sufficient receive buffers before the sender transmits.

The SPT transport backend must manage credits and avoid receive-queue exhaustion.

---

## 8. RDMA Record Framing

SPT records retain the same logical semantics across TCP and RDMA.

Each record includes:

- Protocol version.
- Record type.
- Protection profile.
- Lane identifier.
- Key generation.
- Record sequence.
- Logical stream offset.
- Payload length.
- Authentication tag.

### TCP Mapping

TCP is a byte stream.

The TCP backend must parse framing boundaries from received bytes.

### RDMA SEND/RECV Mapping

RDMA SEND/RECV preserves message boundaries.

The initial implementation may map one SPT record to one RDMA message, subject to device limits and negotiated maximum message sizes.

The record encoding must remain transport-independent.

A future optimized RDMA backend may support batching multiple records or splitting larger records into transport operations without changing logical-stream semantics.

---

## 9. Security Architecture

The existing SPT security model remains mandatory.

### Control Plane

Always:

- TLS 1.3.
- Authenticated peers.
- Confidential control messages.
- Authenticated transport negotiation.
- Authenticated lane establishment.

### Data Plane

SPT supports the protection profiles defined by the selective-protection extension.

| Profile | Confidentiality | Integrity/authenticity |
|---|---|---|
| `SPT_PROTECTION_CONFIDENTIAL` | Yes | Yes |
| `SPT_PROTECTION_AUTHENTICATED` | No | Yes |

Authentication-only records are permitted only for explicitly approved non-sensitive data.

The receiver must enforce the negotiated minimum protection policy.

### RDMA Access Permissions Are Not Cryptographic Authentication

RDMA memory keys and access permissions are resource-access mechanisms.

They do not replace end-to-end record authentication.

Every SPT record must be cryptographically verified before its contents are delivered to the application.

---

## 10. RDMA and Encryption Performance

RDMA is attractive because it can reduce CPU involvement and memory copying.

However, software encryption can reduce some of these benefits.

### Confidential Records

A possible implementation:

```text
Application plaintext
       |
AEAD encryption
       |
Ciphertext staging buffer
       |
RDMA SEND
```

At the receiver:

```text
RDMA receive buffer
       |
AEAD authentication/decryption
       |
Application plaintext buffer
```

This may require additional memory movement.

### Authenticated-Only Records

For explicitly public bulk data:

```text
Application plaintext
       |
MAC calculation
       |
RDMA SEND
```

The payload does not require encryption.

This may enable more efficient use of registered buffers, although the MAC still requires reading the data.

### Future Hardware Crypto

Some hardware platforms may provide cryptographic offload capabilities.

Such capabilities must be discovered and evaluated rather than assumed.

SPT must not depend on a particular NIC's proprietary encryption interface.

---

## 11. Memory Registration and Buffer Management

RDMA requires careful management of registered memory.

The backend should support:

- Registered buffer pools.
- Reusable receive buffers.
- Bounded outstanding operations.
- Reference-counted buffer lifetime.
- Completion-based release.
- NUMA-local allocation.
- Registration caching where appropriate.

### Buffer Lifetime

A submitted buffer must remain valid until the relevant operation completes.

For SEND operations, a successful local completion generally indicates the sender may reuse the associated send buffer; it does not, by itself, establish that the remote SPT application has consumed or committed the logical bytes.

SPT must distinguish:

- Local transport completion.
- Remote record authentication.
- Logical stream delivery.
- Application consumption.

These are different events.

### Memory Safety

The RDMA backend must prevent:

- Use-after-free of registered buffers.
- Reuse before completion.
- Access after memory-region invalidation.
- Unbounded receive-buffer allocation.
- Incorrect cleanup after QP failure.

---

## 12. Completion-Based I/O Abstraction

RDMA reinforces the need for a transport-neutral completion interface.

The SPT core must not depend exclusively on file-descriptor readiness.

A conceptual internal interface:

```c
struct spt_transport_ops {
    int (*connect)(void *lane);

    int (*submit_send)(
        void *lane,
        const struct spt_buffer *buffer
    );

    int (*post_receive)(
        void *lane,
        struct spt_buffer *buffer
    );

    int (*progress)(
        void *lane,
        unsigned int budget
    );

    int (*drain)(void *lane);

    void (*close)(void *lane);
};
```

This interface is illustrative.

The final design must also specify:

- Operation identifiers.
- Completion callbacks.
- Error propagation.
- Buffer ownership.
- Cancellation.
- Concurrency rules.
- Resource lifetime.
- Lane state transitions.

### TCP Backend

Implements operations using nonblocking TCP sockets.

### RDMA Backend

Implements operations using RDMA work requests and completion queues.

### Kernel Backend

May later implement the same logical operations using kernel networking and RDMA APIs.

---

## 13. Event-Driven Integration and XRootD

The RDMA backend must remain compatible with externally managed event loops.

XRootD should not be required to replace its scheduler or pollers.

Possible integration mechanisms include:

- Completion-channel notifications.
- Host-managed completion polling.
- Dedicated RDMA progress workers.
- Bounded CQ polling from application workers.

The best approach must be measured.

### Important Requirement

**The SPT core must not assume that a transport lane corresponds to a file descriptor.**

A TCP lane is typically represented by a socket.

An RDMA lane is represented by RDMA resources such as a QP and completion queues.

The application-facing logical stream must remain unchanged.

### Avoiding Poller Bottlenecks

RDMA completion processing should be distributed carefully.

Potential bottlenecks include:

- Too many QPs sharing one overloaded CQ.
- Excessive completion notifications.
- Busy polling without sufficient useful work.
- Cross-NUMA completion handling.
- Centralized reassembly locks.

The RDMA backend should support configurable CQ placement and completion-processing budgets.

---

## 14. RDMA Flow Control

SPT requires flow control independently of the underlying transport.

For RDMA SEND/RECV, the receiver must have sufficient posted receive buffers.

The backend should maintain receive credits.

Conceptually:

```text
Receiver posts N receive buffers
             |
Advertises available credits
             |
Sender transmits within credit limit
             |
Receive completions free/recycle buffers
             |
Credits are replenished
```

SPT also maintains logical-stream flow control.

The sender must not transmit unlimited out-of-order records merely because RDMA transport resources are available.

### Two Levels of Flow Control

**Transport-level credits:** Prevent exhaustion of RDMA receive resources.

**SPT logical-stream credits:** Bound reassembly and application receive memory.

Both are necessary.

---

## 15. Reliability and Failure Semantics

Reliable Connected RDMA provides reliable, ordered delivery within a QP under its transport semantics.

However, this does not automatically provide one ordered stream across multiple QPs.

SPT still needs:

- Logical offsets.
- Duplicate detection.
- Reassembly.
- Session failure handling.
- Delivery accounting.

### Initial Failure Policy

For the first RDMA prototype:

- A fatal QP failure fails the SPT session.
- All outstanding operations are canceled or completed with errors.
- Buffers are released safely.
- The control channel reports the failure.
- No automatic cross-lane retransmission is required.

Future versions may support recovery over surviving lanes.

### TCP Fallback

An optional fallback from RDMA to TCP must be explicitly negotiated.

Fallback must preserve:

- Session identity.
- Protection policy.
- Logical stream correctness.
- Cryptographic key separation.
- Delivery accounting.

A transport failure must not silently cause a security downgrade.

---

## 16. RDMA WRITE: Future Extension

RDMA WRITE may offer additional performance benefits by allowing direct placement into receiver-provided memory.

However, it introduces greater complexity.

### Required Mechanisms

- Receiver-authorized memory regions.
- Secure exchange of remote addresses and access keys.
- Buffer registration and lifetime tracking.
- Placement credits.
- Completion notification.
- Protection against unauthorized or stale writes.
- Authentication before application consumption.

### Security Consideration

A successful RDMA WRITE does not imply that the received data has passed SPT cryptographic authentication.

The receiver must not expose or consume unverified data.

### Proposed Future Design

The receiver allocates and registers a bounded set of buffers.

The sender receives authenticated placement authorization.

The sender writes records into authorized buffers.

The receiver is notified that a record is ready.

The receiver verifies the record's authentication tag.

Only then is the data made available to the logical stream.

The exact memory ordering, notification, and authorization protocol requires separate specification.

**RDMA WRITE should not be part of the first RDMA milestone.**

---

## 17. Transport Selection and Scaling

The existing `ps_autoscale` controller is designed primarily for parallel TCP.

RDMA requires different heuristics.

### TCP

Potential reasons to increase lane count:

- RSS distribution.
- CPU parallelism.
- TCP processing bottlenecks.
- Crypto worker utilization.

### RDMA

Potential reasons to increase QP count:

- QP throughput limits.
- CQ processing distribution.
- NUMA locality.
- Hardware queue limitations.
- Parallel application demand.

The number of RDMA QPs must not be calculated directly from TCP bandwidth-delay-product heuristics.

### Initial RDMA Policy

Use a fixed number of QPs.

Recommended initial experiments:

```text
1 QP
2 QPs
4 QPs
8 QPs
```

Automatic RDMA lane scaling is deferred.

### Transport Selection

A future API may support:

```c
typedef enum {
    SPT_TRANSPORT_AUTO = 0,
    SPT_TRANSPORT_TCP,
    SPT_TRANSPORT_RDMA_RC
} spt_transport_preference_t;
```

Transport selection must respect:

- Peer capabilities.
- Local device availability.
- Security policy.
- Deployment configuration.
- Application requirements.

---

## 18. Proposed Configuration Extension

Conceptual configuration:

```c
struct ps_transport_options {
    spt_transport_preference_t preference;

    unsigned int min_lanes;
    unsigned int max_lanes;
    unsigned int initial_lanes;

    size_t frame_size;
    size_t receive_window;

    unsigned int rdma_send_depth;
    unsigned int rdma_recv_depth;

    unsigned int rdma_cq_poll_budget;

    int allow_tcp_fallback;
};
```

The final API should avoid exposing unnecessary RDMA details to applications that use only TCP.

Backend-specific options may be provided through an optional configuration structure.

---

## 19. Benchmark Matrix

| Test | Transport | Lanes | Protection |
|---|---|---:|---|
| A | TCP | 1 | AES-GCM |
| B | Parallel TCP | 2–16 | AES-GCM |
| C | Parallel TCP | 2–16 | Authentication-only |
| D | RDMA RC SEND/RECV | 1 | AES-GCM |
| E | RDMA RC SEND/RECV | 2–8 | AES-GCM |
| F | RDMA RC SEND/RECV | 1 | Authentication-only |
| G | RDMA RC SEND/RECV | 2–8 | Authentication-only |
| H | Native RDMA benchmark | Hardware-dependent | Baseline |
| I | Future RDMA WRITE | 1–8 | SPT protection |

### Metrics

- Application goodput.
- CPU cycles per byte.
- CPU utilization.
- Memory bandwidth.
- Cache misses.
- Registered memory footprint.
- Memory registration overhead.
- CQ processing overhead.
- QP count.
- Completion latency.
- NUMA traffic.
- Crypto throughput.
- Reassembly memory.
- Failure recovery behavior.

### Key Questions

1. Does RDMA provide better throughput than parallel TCP?
2. Does RDMA achieve similar throughput with fewer CPU cores?
3. Is one RDMA QP sufficient?
4. Does authentication-only mode improve RDMA performance?
5. Does software AEAD eliminate much of RDMA's advantage?
6. How much overhead does SPT framing and reassembly add?
7. Can XRootD use the same logical-stream API with both backends?

---

## 20. Development Roadmap

### Phase 1 — Transport-Neutral Core

Ensure the SPT core does not depend on:

- TCP file descriptors.
- `epoll` readiness.
- One thread per socket.
- TCP-specific socket-count heuristics.

Introduce transport-neutral lanes and completion-based operations.

**Deliverable:** A protocol core capable of supporting TCP and RDMA backends.

### Phase 2 — Stable TCP Implementation

Complete:

- TLS control.
- Parallel TCP data plane.
- AEAD.
- Reassembly.
- Flow control.
- Event-driven integration.
- Fixed and adaptive TCP scaling.

**Deliverable:** Validated SPT over TCP.

### Phase 3 — RDMA Capability Negotiation

Add:

- Transport capability advertisement.
- RDMA lane authorization.
- Authenticated connection metadata.
- Transport selection policy.

**Deliverable:** Secure RDMA session setup.

### Phase 4 — RDMA RC SEND/RECV Backend

Implement:

- `libibverbs` integration.
- Optional `librdmacm` connection management.
- QP creation.
- CQ processing.
- Registered buffer pools.
- Receive credits.
- Fixed QP count.

**Deliverable:** One logical SPT stream over RDMA RC SEND/RECV.

### Phase 5 — RDMA Security Profiles

Implement:

- Confidential AEAD records.
- Authentication-only records where permitted.
- Shared test vectors.
- Receiver-side policy enforcement.

**Deliverable:** Secure RDMA data plane compatible with SPT protection profiles.

### Phase 6 — XRootD Integration

Evaluate:

- External event-loop integration.
- CQ processing.
- Buffer ownership.
- Poller interaction.
- Existing XRootD transport performance.

**Deliverable:** XRootD-compatible RDMA transport experiment.

### Phase 7 — Performance Optimization

Evaluate:

- Registered buffer pools.
- NUMA-local allocation.
- CQ batching.
- Multiple QPs.
- Reduced-copy paths.
- Crypto offload.
- Registration caching.

**Deliverable:** Optimized RDMA backend with reproducible benchmarks.

### Phase 8 — RDMA WRITE Research

Investigate:

- Direct placement.
- Secure memory-region authorization.
- Receiver notification.
- Authentication before delivery.
- Zero-copy feasibility.

**Deliverable:** RDMA WRITE design and experimental prototype.

### Phase 9 — Kernel RDMA Backend

If justified by application requirements:

- Evaluate kernel RDMA APIs.
- Reuse SPT wire protocol.
- Reuse SPT cryptographic test vectors.
- Integrate with the trusted userspace control daemon.

**Deliverable:** Optional kernel RDMA transport backend.

---

## 21. Major Risks

### Increased Architectural Complexity

Supporting TCP and RDMA adds backend interfaces, lifecycle states, and failure modes.

**Mitigation:** Keep the initial TCP implementation simple and make RDMA optional.

### RDMA Hardware Dependency

RDMA requires suitable NICs, drivers, and network configuration.

**Mitigation:** Preserve TCP as the universally available backend.

### Memory Registration Overhead

Registering and deregistering buffers can be expensive.

**Mitigation:** Use reusable registered buffer pools.

### Cryptographic Copy Overhead

Software AEAD may reduce RDMA's zero-copy advantage.

**Mitigation:** Benchmark carefully and investigate reduced-copy processing.

### Completion Processing Bottlenecks

Poor CQ placement may limit throughput.

**Mitigation:** Configurable CQ processing and NUMA-aware scheduling.

### Security Misconfiguration

RDMA access permissions must not be confused with cryptographic authentication.

**Mitigation:** Preserve mandatory SPT record authentication.

### Protocol Complexity

Transport fallback and multiple lane types increase protocol state complexity.

**Mitigation:** Begin with one transport type per SPT session.

---

## 22. Architectural Decisions

| Topic | Decision |
|---|---|
| Application abstraction | One ordered logical stream |
| Transport abstraction | Transport-neutral lanes |
| Initial backend | Parallel TCP |
| Optional backend | RDMA |
| Initial RDMA mode | RC SEND/RECV |
| Future RDMA mode | RDMA WRITE |
| RDMA userspace library | libibverbs |
| Connection management | Evaluate librdmacm |
| Control plane | TLS 1.3 over TCP |
| RDMA lane authentication | Bound to SPT session |
| Confidential data | Standard AEAD |
| Public bulk data | Authenticated-only when authorized |
| Unauthenticated records | Not supported |
| Initial RDMA lane count | Fixed |
| TCP autoscaling | Existing ps_autoscale |
| RDMA autoscaling | Future research |
| Event-loop integration | Completion-based |
| XRootD integration | Shared SPT logical-stream API |
| Kernel compatibility | Future optional backend |
| Transport fallback | Explicitly negotiated |
| Initial mixed TCP/RDMA lanes | Not supported |

---

## 23. Open Research Questions

1. Can SPT over RDMA match native RDMA bulk-transfer performance?
2. How much overhead does SPT record authentication add?
3. Can a single RC QP saturate a 400 or 800 GbE link?
4. When do multiple QPs improve throughput?
5. How should QPs and CQs be mapped to CPU cores?
6. How much does memory registration affect short transfers?
7. Can authentication-only RDMA approach zero-copy performance?
8. How should AEAD be combined with registered memory?
9. Can the SPT core support both TCP and RDMA without excessive abstraction overhead?
10. What is the best XRootD integration model?
11. How should TCP fallback preserve logical delivery state?
12. What is required for safe RDMA WRITE-based direct placement?
13. Would a kernel RDMA backend provide additional benefits?

---

## 24. Conclusion

RDMA is a promising optional transport backend for libparsock.

Its primary benefit is potentially reducing CPU overhead and memory movement compared with conventional TCP, especially for large scientific data transfers.

The proposed design preserves the existing SPT principles:

- One logical ordered byte stream.
- One authenticated session.
- TLS 1.3 control plane.
- Transport-independent framing.
- Strong record authentication.
- Optional confidentiality for explicitly approved bulk data.
- Event-driven server integration.
- Future kernel compatibility.

The architecture generalizes TCP subflows into transport-neutral lanes, allowing the same SPT core to operate over TCP sockets or RDMA queue pairs.

**The recommended strategy is to complete and benchmark SPT over parallel TCP first, then add RDMA RC SEND/RECV as an independent optional backend.**

RDMA WRITE, advanced zero-copy operation, dynamic QP scaling, and kernel RDMA support should remain later research milestones.

---

## 25. Wire Format Implemented Here

Integers are big-endian. These messages travel on the TLS control connection. A session uses one data-plane transport. Mixed TCP and RDMA lanes are not used.

`TRANSPORT_OFFER` (type 15) is 24 bytes, client to server, after the hellos when the client preference is `auto` or `rdma`:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | preference: 1 TCP, 2 RDMA RC |
| 1 | 1 | fallback: 1 if TCP is authorized |
| 2 | 2 | reserved, must be 0 |
| 4 | 4 | initial lanes |
| 8 | 4 | maximum lanes |
| 12 | 4 | send depth |
| 16 | 4 | receive depth |
| 20 | 4 | maximum SPT message size |

`TRANSPORT_SELECT` (type 16) is 16 bytes, server to client:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | selected transport |
| 1 | 1 | reserved, must be 0 |
| 2 | 2 | RDMA CM port, 0 for TCP |
| 4 | 4 | lanes |
| 8 | 4 | send depth |
| 12 | 4 | receive depth |

RDMA lanes then use `SUBFLOW_OPEN` and `SUBFLOW_ACCEPT`. The RDMA CM private data is a 32-byte HMAC-SHA256 token, not a credential by itself. The HMAC key is the SPT root. The HMAC input, with no NULs, is:

```text
"spt-rdma-v1" (11) || u32 lane_id || client_nonce (32) || server_nonce (32) || session_id (32)
```

The server accepts a connection only when that token matches an authorized lane. The first RDMA message is the existing AEAD `JOIN` record. There is no cleartext preface. One SPT record is one RC SEND.

`RDMA_CREDIT` (type 17) is 8 bytes: lane id, then the absolute number of receive buffers the sender may have posted. The initial credit is the negotiated receive depth. A fatal queue-pair error fails the session.

The listener is IPv4. `ps_options.transport` selects `PS_TRANSPORT_TCP` (the default), `PS_TRANSPORT_AUTO`, or `PS_TRANSPORT_RDMA_RC`. Automatic mode and `--tcp-fallback` may select TCP. An explicit RDMA preference does not fall back unless that option is set. The first QP count is fixed at the negotiated lane count, at most 16.

## References

- [Linux RDMA Userspace API](https://docs.kernel.org/infiniband/user_verbs.html)
- [rdma-core](https://github.com/linux-rdma/rdma-core)
- [libibverbs Manual Pages](https://man7.org/linux/man-pages/man7/rdma_cm.7.html)
- [RDMA CM](https://man7.org/linux/man-pages/man7/rdma_cm.7.html)
- [libfabric](https://ofiwg.github.io/libfabric/)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 5116 — AEAD Interface](https://www.rfc-editor.org/rfc/rfc5116)
- [Linux Kernel Crypto API](https://docs.kernel.org/crypto/index.html)

---

**Extension:** SPT RDMA Transport Backend
**Initial transport:** RDMA RC SEND/RECV
**Control:** TLS 1.3 over TCP
**Security:** SPT AEAD or authenticated-only records
**Development priority:** After the parallel TCP implementation and transport abstraction are stable.
