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
- A header-only C++17 wrapper in `include/parsock.hpp` (`parsock::options`, `connection`, `listener`, `session`)
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

Benchmark between two machines. Use the same `--aead`, `--sockets`, and `--protection` on both ends. Authenticated mode keeps the payload in plaintext and still authenticates every record. The server certificate encrypts the control connection. A client certificate is optional. A server started without `--cert` and `--key` writes a self-signed certificate for that connection.

```sh
./build/spt_bench server --bind 0.0.0.0 --port 8443 \
    --aead aes-256-gcm --sockets 4 --protection confidential
./build/spt_bench client 192.168.1.10 8443 \
    --aead aes-256-gcm --sockets 4 --protection confidential --bytes 8G
```

A terminal shows transmit and receive rate, with a sparkline of about the last minute. Redirected output is CSV. `--send` and `--recv` move files in either direction at the same time. `spt_bench suite` repeats confidential AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305, plus authenticated HMAC, on loopback.

## Layout

- `include/parsock.h` — C application API
- `include/parsock.hpp` — header-only C++17 wrapper
- `include/spt_wire.h` — experimental wire codec and key schedule
- `src/session.c` — protocol core
- `src/drive.c` — TLS pump and readiness entry points
- `src/standalone.c` — poll thread, listener, and blocking API
