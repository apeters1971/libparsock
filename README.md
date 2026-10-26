# libparsock

Userspace proof of concept for **Secure Parallel Transport (SPT/0.1)**.

One reliable, ordered, bidirectional byte stream is carried on several ordinary TCP sockets. A TLS 1.3 control connection authenticates the peers and stays up for the session. Data sockets carry custom AEAD records, not TLS records. The protocol core does not own the event loop: the same session runs under a library poll thread or under an external poller.

This tree is a research implementation. It is not a production transport, it does not modify the kernel or OpenSSL, and it has not had a security review. The wire format is experimental and is written down in [docs/spt-0.1.md](docs/spt-0.1.md).

## Build

OpenSSL 3 is required. On macOS with Homebrew:

```sh
cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
cmake --build build
ctest --test-dir build --output-on-failure
```

The CMake build looks for Homebrew OpenSSL 3 on Apple automatically when that prefix exists. AddressSanitizer:

```sh
cmake -S . -B build-asan -DPARSOCK_ASAN=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

`PS_DEBUG=1` prints session traces to stderr.

## What is implemented

- Fixed, automatic, and advisory socket counts
- TLS 1.3 control plane via unmodified OpenSSL
- AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 data records
- Optional authentication-only data records (HMAC-SHA-256) when both peers set `min_protection` to authenticated. `ps_send` stays confidential. `ps_send_protected` selects the profile for one buffer. The library copies that buffer.
- Ordered reassembly, absolute receive windows, and a generation-based rekey
- A blocking `ps_connect` / `ps_send` / `ps_recv` API
- An embedded readiness API (`ps_on_readable`, `ps_on_writable`, `ps_embed_service`) for an external poller
- Optional crypto worker threads, independent of the socket count

Out of scope for this tree: a kernel client, `sptd`, native XRootD integration, cross-socket retransmission, and io_uring.

## Examples

Generate a certificate once:

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 2 -nodes \
  -subj /CN=127.0.0.1 -addext subjectAltName=DNS:localhost,IP:127.0.0.1
```

Bulk transfer:

```sh
./build/spt_bulk server cert.pem key.pem
./build/spt_bulk client cert.pem key.pem 127.0.0.1 <port> 67108864
```

One HTTP/1.1 GET of a generated body, with no Range requests:

```sh
./build/spt_http server cert.pem key.pem
./build/spt_http client cert.pem key.pem 127.0.0.1 <port> 1048576
```

Set the same `ps_options.aead` on both peers. A ChaCha20 or AES-128-GCM client is rejected by an AES-256-GCM server.

To carry a public response body without payload encryption, both processes pass `public` and the server marks only that body authenticated. The request and response headers stay confidential:

```sh
./build/spt_http server cert.pem key.pem 0 public
./build/spt_http client cert.pem key.pem 127.0.0.1 <port> 1048576 public
```

## Layout

- `include/parsock.h` — application API
- `include/spt_wire.h` — experimental wire codec and key schedule
- `src/session.c` — protocol core
- `src/drive.c` — TLS pump and readiness entry points
- `src/standalone.c` — poll thread, listener, and blocking API
