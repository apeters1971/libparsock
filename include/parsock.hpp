#ifndef PARSOCK_HPP
#define PARSOCK_HPP

/*
 * Header-only C++17 wrapper for the libparsock C API.
 *
 * The library remains C. This header adds RAII, owned option strings, and
 * exceptions. Link the parsock library; do not compile this file alone.
 *
 *   parsock::options opt;
 *   opt.certificate("cert.pem").private_key("key.pem").ca_file("cert.pem")
 *      .server_name("127.0.0.1").sockets(4);
 *   auto conn = parsock::connection::connect("127.0.0.1", port, opt);
 *   conn.send(std::string_view{"hello"});
 *
 * connection::send writes the whole buffer or throws. A throw after some
 * bytes may already have been accepted by the session. recv returns 0 at
 * end of stream. Callbacks on session run on the thread that entered the
 * library and must not re-enter on_readable, on_writable, or service. An
 * exception from a callback is held and rethrown from that call.
 */

#include "parsock.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <type_traits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace parsock {

enum class scale_mode : int {
    fixed = PS_SCALE_FIXED,
    automatic = PS_SCALE_AUTO,
    advisory = PS_SCALE_ADVISORY
};

enum class aead : int {
    aes_256_gcm = PS_AEAD_AES_256_GCM,
    chacha20_poly1305 = PS_AEAD_CHACHA20_POLY1305,
    aes_128_gcm = PS_AEAD_AES_128_GCM
};

enum class protection : int {
    confidential = PS_PROTECTION_CONFIDENTIAL,
    authenticated = PS_PROTECTION_AUTHENTICATED
};

enum class errc : int {
    ok = PS_OK,
    invalid = PS_ERR_INVAL,
    nomem = PS_ERR_NOMEM,
    tls = PS_ERR_TLS,
    protocol = PS_ERR_PROTO,
    crypto = PS_ERR_CRYPTO,
    closed = PS_ERR_CLOSED,
    flow = PS_ERR_FLOW,
    io = PS_ERR_IO,
    again = PS_ERR_AGAIN,
    authentication = PS_ERR_AUTH,
    limit = PS_ERR_LIMIT,
    timeout = PS_ERR_TIMEOUT
};

enum class session_state : int {
    init = PS_STATE_INIT,
    handshake = PS_STATE_HANDSHAKE,
    negotiating = PS_STATE_NEGOTIATING,
    open = PS_STATE_OPEN,
    closing = PS_STATE_CLOSING,
    failed = PS_STATE_FAILED,
    closed = PS_STATE_CLOSED
};

using stats = ::ps_stats;
using scale_advice = ::ps_scale_advice;

class error_category_impl : public std::error_category {
public:
    const char *name() const noexcept override { return "parsock"; }
    std::string message(int condition) const override { return ps_strerror(condition); }
};

inline const std::error_category &error_category()
{
    static const error_category_impl category;
    return category;
}

inline std::error_code make_error_code(errc code) noexcept
{
    return {static_cast<int>(code), error_category()};
}

class failure : public std::system_error {
public:
    explicit failure(errc code) : std::system_error(make_error_code(code)) {}
    explicit failure(int code) : std::system_error(code, error_category()) {}
};

struct watch {
    int fd = -1;
    bool want_read = false;
    bool want_write = false;
};

struct endpoints {
    std::uint16_t control = 0;
    std::uint16_t data = 0;
};

struct preface {
    std::array<std::uint8_t, 32> session_id{};
    std::uint32_t subflow_id = 0;
};

struct transfer {
    std::size_t count = 0;
    bool blocked = false;
    bool eof = false;
};

struct io_handlers {
    std::function<void(int fd, bool want_read, bool want_write)> want_io;
    std::function<void(int fd)> stop_io;
    std::function<void()> stream_readable;
    std::function<void()> stream_writable;
    std::function<void(errc)> on_error;
    std::function<void()> poke;
    std::exception_ptr caught;
};

class options {
public:
    options()
    {
        ps_options_init(&opt_);
        tls_.verify_peer = 1;
        bind();
    }

    options(const options &other)
        : opt_(other.opt_), tls_(other.tls_), cert_(other.cert_), key_(other.key_), ca_(other.ca_),
          name_(other.name_)
    {
        bind();
    }

    options &operator=(const options &other)
    {
        if (this != &other) {
            opt_ = other.opt_;
            tls_ = other.tls_;
            cert_ = other.cert_;
            key_ = other.key_;
            ca_ = other.ca_;
            name_ = other.name_;
            bind();
        }
        return *this;
    }

    options(options &&other) noexcept
        : opt_(other.opt_), tls_(other.tls_), cert_(std::move(other.cert_)),
          key_(std::move(other.key_)), ca_(std::move(other.ca_)), name_(std::move(other.name_))
    {
        bind();
        other.bind();
    }

    options &operator=(options &&other) noexcept
    {
        if (this != &other) {
            opt_ = other.opt_;
            tls_ = other.tls_;
            cert_ = std::move(other.cert_);
            key_ = std::move(other.key_);
            ca_ = std::move(other.ca_);
            name_ = std::move(other.name_);
            bind();
            other.bind();
        }
        return *this;
    }

    options &scale(scale_mode mode)
    {
        opt_.scale_mode = static_cast<ps_scale_mode_t>(mode);
        return *this;
    }
    options &sockets(unsigned count)
    {
        opt_.min_sockets = count;
        opt_.max_sockets = count;
        opt_.initial_sockets = count;
        return *this;
    }
    options &sockets(unsigned min_count, unsigned max_count, unsigned initial)
    {
        opt_.min_sockets = min_count;
        opt_.max_sockets = max_count;
        opt_.initial_sockets = initial;
        return *this;
    }
    options &workers(unsigned count)
    {
        opt_.worker_threads = count;
        return *this;
    }
    options &scale_interval(std::uint32_t milliseconds)
    {
        opt_.scale_interval_ms = milliseconds;
        return *this;
    }
    options &min_transfer_size(std::uint64_t bytes)
    {
        opt_.min_transfer_size = bytes;
        return *this;
    }
    options &frame_size(std::size_t bytes)
    {
        opt_.frame_size = bytes;
        return *this;
    }
    options &receive_window(std::size_t bytes)
    {
        opt_.receive_window = bytes;
        return *this;
    }
    options &cipher(aead algorithm)
    {
        opt_.aead = static_cast<ps_aead_t>(algorithm);
        return *this;
    }
    options &minimum_protection(protection floor)
    {
        opt_.min_protection = static_cast<ps_protection_t>(floor);
        return *this;
    }
    options &connect_timeout(std::uint32_t milliseconds)
    {
        opt_.connect_timeout_ms = milliseconds;
        return *this;
    }
    options &io_timeout(std::uint32_t milliseconds)
    {
        opt_.io_timeout_ms = milliseconds;
        return *this;
    }
    options &poller_budget(std::size_t bytes, unsigned records)
    {
        opt_.max_poller_bytes = bytes;
        opt_.max_poller_records = records;
        return *this;
    }
    options &certificate(std::string path)
    {
        cert_ = std::move(path);
        bind();
        return *this;
    }
    options &private_key(std::string path)
    {
        key_ = std::move(path);
        bind();
        return *this;
    }
    options &ca_file(std::string path)
    {
        ca_ = std::move(path);
        bind();
        return *this;
    }
    options &server_name(std::string name)
    {
        name_ = std::move(name);
        bind();
        return *this;
    }
    options &verify_peer(bool enabled)
    {
        tls_.verify_peer = enabled ? 1 : 0;
        return *this;
    }
    options &allow_insecure(bool enabled)
    {
        tls_.allow_insecure = enabled ? 1 : 0;
        return *this;
    }

    const ps_options &native() const noexcept { return opt_; }

private:
    void bind() noexcept
    {
        tls_.cert_file = cert_.empty() ? nullptr : cert_.c_str();
        tls_.key_file = key_.empty() ? nullptr : key_.c_str();
        tls_.ca_file = ca_.empty() ? nullptr : ca_.c_str();
        tls_.server_name = name_.empty() ? nullptr : name_.c_str();
        opt_.tls = &tls_;
    }

    ps_options opt_{};
    ps_tls_config tls_{};
    std::string cert_;
    std::string key_;
    std::string ca_;
    std::string name_;
};

namespace detail {

inline int code_of(std::ptrdiff_t rc) noexcept
{
    if (rc >= 0)
        return PS_OK;
    const int code = static_cast<int>(-rc);
    if (code < PS_ERR_INVAL || code > PS_ERR_TIMEOUT)
        return PS_ERR_IO;
    return code;
}

inline void check(int rc)
{
    if (rc < 0)
        throw failure(code_of(rc));
}

template <class Fn, class... Args>
void invoke(io_handlers *handlers, Fn &fn, Args &&...args)
{
    if (!fn || (handlers && handlers->caught))
        return;
    try {
        fn(std::forward<Args>(args)...);
    } catch (...) {
        if (handlers)
            handlers->caught = std::current_exception();
    }
}

inline void want_io_thunk(void *ctx, int fd, int want_read, int want_write)
{
    auto *handlers = static_cast<io_handlers *>(ctx);
    invoke(handlers, handlers->want_io, fd, want_read != 0, want_write != 0);
}

inline void stop_io_thunk(void *ctx, int fd)
{
    auto *handlers = static_cast<io_handlers *>(ctx);
    invoke(handlers, handlers->stop_io, fd);
}

inline void readable_thunk(void *ctx)
{
    auto *handlers = static_cast<io_handlers *>(ctx);
    invoke(handlers, handlers->stream_readable);
}

inline void writable_thunk(void *ctx)
{
    auto *handlers = static_cast<io_handlers *>(ctx);
    invoke(handlers, handlers->stream_writable);
}

inline void error_thunk(void *ctx, int error)
{
    auto *handlers = static_cast<io_handlers *>(ctx);
    invoke(handlers, handlers->on_error, static_cast<errc>(error));
}

inline void poke_thunk(void *ctx)
{
    auto *handlers = static_cast<io_handlers *>(ctx);
    invoke(handlers, handlers->poke);
}

inline ps_io_cbs callbacks_for(io_handlers *handlers)
{
    ps_io_cbs cbs;
    std::memset(&cbs, 0, sizeof(cbs));
    cbs.ctx = handlers;
    cbs.want_io = want_io_thunk;
    cbs.stop_io = stop_io_thunk;
    cbs.stream_readable = readable_thunk;
    cbs.stream_writable = writable_thunk;
    cbs.session_error = error_thunk;
    cbs.poke = poke_thunk;
    return cbs;
}

} // namespace detail

class connection {
    friend class listener;

public:
    connection() noexcept = default;
    connection(const connection &) = delete;
    connection &operator=(const connection &) = delete;

    connection(connection &&other) noexcept : conn_(std::exchange(other.conn_, nullptr)) {}

    connection &operator=(connection &&other) noexcept
    {
        if (this != &other) {
            reset();
            conn_ = std::exchange(other.conn_, nullptr);
        }
        return *this;
    }

    ~connection() { reset(); }

    static connection connect(std::string_view host, std::uint16_t port, const options &opt)
    {
        const std::string host_name(host);
        ps_connection_t *raw = ps_connect(host_name.c_str(), port, &opt.native());
        if (!raw)
            throw failure(errc::io);
        return connection(raw);
    }

    explicit operator bool() const noexcept { return conn_ != nullptr; }

    void send(const void *data, std::size_t length)
    {
        send(data, length, protection::confidential);
    }

    void send(std::string_view bytes)
    {
        send(bytes.data(), bytes.size(), protection::confidential);
    }

    void send(const std::vector<std::uint8_t> &bytes, protection profile = protection::confidential)
    {
        send(bytes.data(), bytes.size(), profile);
    }

    void send(std::string_view bytes, protection profile)
    {
        send(bytes.data(), bytes.size(), profile);
    }

    void send(const void *data, std::size_t length, protection profile)
    {
        if (!conn_)
            throw failure(errc::invalid);
        const ssize_t n = ps_send_protected(conn_, data, length, static_cast<ps_protection_t>(profile));
        if (n < 0)
            throw failure(detail::code_of(n));
        if (static_cast<std::size_t>(n) != length)
            throw failure(errc::io);
    }

    std::size_t recv(void *data, std::size_t length)
    {
        if (!conn_)
            throw failure(errc::invalid);
        if (length == 0)
            return 0;
        const ssize_t n = ps_recv(conn_, data, length);
        if (n < 0)
            throw failure(detail::code_of(n));
        return static_cast<std::size_t>(n);
    }

    std::vector<std::uint8_t> recv_some(std::size_t maximum)
    {
        std::vector<std::uint8_t> out(maximum);
        const std::size_t n = recv(out.data(), out.size());
        out.resize(n);
        return out;
    }

    void shutdown_write()
    {
        if (!conn_)
            throw failure(errc::invalid);
        detail::check(ps_shutdown(conn_, SHUT_WR));
    }

    void rekey()
    {
        if (!conn_)
            throw failure(errc::invalid);
        detail::check(ps_rekey(conn_));
    }

    session_state state() const
    {
        if (!conn_)
            return session_state::closed;
        return static_cast<session_state>(ps_connection_state(conn_));
    }

    errc last_error() const
    {
        if (!conn_)
            return errc::invalid;
        return static_cast<errc>(ps_connection_error(conn_));
    }

    stats statistics() const
    {
        stats out{};
        if (!conn_ || ps_connection_stats(conn_, &out) != 0)
            throw failure(errc::invalid);
        return out;
    }

    scale_advice advice() const
    {
        scale_advice out{};
        if (!conn_ || ps_connection_advice(conn_, &out) != 0)
            throw failure(errc::invalid);
        return out;
    }

    void close() noexcept { reset(); }

    ps_connection_t *native() noexcept { return conn_; }

private:
    explicit connection(ps_connection_t *raw) noexcept : conn_(raw) {}

    void reset() noexcept
    {
        if (conn_) {
            ps_close(conn_);
            conn_ = nullptr;
        }
    }

    ps_connection_t *conn_ = nullptr;
};

class listener {
public:
    listener() noexcept = default;
    listener(const listener &) = delete;
    listener &operator=(const listener &) = delete;

    listener(listener &&other) noexcept : ln_(std::exchange(other.ln_, nullptr)) {}

    listener &operator=(listener &&other) noexcept
    {
        if (this != &other) {
            reset();
            ln_ = std::exchange(other.ln_, nullptr);
        }
        return *this;
    }

    ~listener() { reset(); }

    static listener listen(std::string_view host, std::uint16_t port, const options &opt)
    {
        const std::string host_name(host);
        ps_listener_t *raw = ps_listen(host_name.c_str(), port, &opt.native());
        if (!raw)
            throw failure(errc::io);
        return listener(raw);
    }

    explicit operator bool() const noexcept { return ln_ != nullptr; }

    connection accept()
    {
        if (!ln_)
            throw failure(errc::invalid);
        ps_connection_t *raw = ps_accept(ln_);
        if (!raw)
            throw failure(errc::io);
        return connection(raw);
    }

    endpoints ports() const
    {
        if (!ln_)
            throw failure(errc::invalid);
        endpoints out;
        if (ps_listener_port(ln_, &out.control, &out.data) != 0)
            throw failure(errc::io);
        return out;
    }

    void close() noexcept { reset(); }

    ps_listener_t *native() noexcept { return ln_; }

private:
    explicit listener(ps_listener_t *raw) noexcept : ln_(raw) {}

    void reset() noexcept
    {
        if (ln_) {
            ps_listener_close(ln_);
            ln_ = nullptr;
        }
    }

    ps_listener_t *ln_ = nullptr;
};

class session {
public:
    session() noexcept = default;
    session(const session &) = delete;
    session &operator=(const session &) = delete;

    session(session &&other) noexcept
        : session_(std::exchange(other.session_, nullptr)), handlers_(std::move(other.handlers_))
    {
    }

    session &operator=(session &&other) noexcept
    {
        if (this != &other) {
            reset();
            session_ = std::exchange(other.session_, nullptr);
            handlers_ = std::move(other.handlers_);
        }
        return *this;
    }

    ~session() { reset(); }

    static session create(bool server, const options &opt, io_handlers handlers = {})
    {
        session created;
        created.handlers_ = std::make_unique<io_handlers>(std::move(handlers));
        const ps_io_cbs cbs = detail::callbacks_for(created.handlers_.get());
        created.session_ = ps_embed_create(server ? 1 : 0, &opt.native(), &cbs);
        if (!created.session_)
            throw failure(errc::tls);
        return created;
    }

    explicit operator bool() const noexcept { return session_ != nullptr; }

    void set_control(int fd)
    {
        require();
        detail::check(ps_embed_set_control(session_, fd));
        rethrow();
    }

    void set_data_port(std::uint16_t port)
    {
        require();
        detail::check(ps_embed_set_data_port(session_, port));
        rethrow();
    }

    void set_peer(const sockaddr *address, socklen_t length)
    {
        require();
        detail::check(ps_embed_set_peer(session_, address, length));
        rethrow();
    }

    void adopt_subflow(std::uint32_t subflow_id, int fd)
    {
        require();
        detail::check(ps_embed_adopt_subflow(session_, subflow_id, fd));
        rethrow();
    }

    std::array<std::uint8_t, 32> session_id() const
    {
        require();
        std::array<std::uint8_t, 32> id{};
        detail::check(ps_embed_session_id(session_, id.data()));
        return id;
    }

    void service()
    {
        require();
        detail::check(ps_embed_service(session_));
        rethrow();
    }

    void shutdown_write()
    {
        require();
        detail::check(ps_embed_shutdown_write(session_));
        rethrow();
    }

    void on_readable(int fd)
    {
        require();
        detail::check(ps_on_readable(session_, fd));
        rethrow();
    }

    void on_writable(int fd)
    {
        require();
        detail::check(ps_on_writable(session_, fd));
        rethrow();
    }

    transfer try_send(const void *data, std::size_t length, protection profile = protection::confidential)
    {
        require();
        ps_send_descriptor desc;
        desc.buffer = data;
        desc.length = length;
        desc.protection = static_cast<ps_protection_t>(profile);
        desc.completion_context = nullptr;
        std::size_t accepted = 0;
        const int rc = ps_submit_send_protected(session_, &desc, &accepted);
        rethrow();
        transfer out;
        out.count = accepted;
        if (rc == -PS_ERR_AGAIN || rc == -PS_ERR_FLOW) {
            out.blocked = true;
            return out;
        }
        detail::check(rc);
        return out;
    }

    transfer try_recv(void *data, std::size_t length)
    {
        require();
        std::size_t received = 0;
        const int rc = ps_submit_recv(session_, data, length, &received);
        rethrow();
        transfer out;
        if (rc == -PS_ERR_AGAIN) {
            out.blocked = true;
            return out;
        }
        detail::check(rc);
        out.count = received;
        out.eof = received == 0;
        return out;
    }

    std::vector<watch> watches() const
    {
        require();
        ps_watch raw[PS_MAX_SUBFLOWS + 1];
        const int n = ps_session_watches(session_, raw, PS_MAX_SUBFLOWS + 1);
        std::vector<watch> out;
        out.reserve(static_cast<std::size_t>(n > 0 ? n : 0));
        for (int i = 0; i < n; i++) {
            watch item;
            item.fd = raw[i].fd;
            item.want_read = raw[i].want_read != 0;
            item.want_write = raw[i].want_write != 0;
            out.push_back(item);
        }
        return out;
    }

    session_state state() const
    {
        if (!session_)
            return session_state::closed;
        return static_cast<session_state>(ps_session_state(session_));
    }

    errc last_error() const
    {
        if (!session_)
            return errc::invalid;
        return static_cast<errc>(ps_session_error(session_));
    }

    stats statistics() const
    {
        require();
        stats out{};
        detail::check(ps_session_stats(session_, &out));
        return out;
    }

    scale_advice advice() const
    {
        require();
        scale_advice out{};
        detail::check(ps_session_advice(session_, &out));
        return out;
    }

    void close() noexcept { reset(); }

    ps_session_t *native() noexcept { return session_; }

private:
    void require() const
    {
        if (!session_)
            throw failure(errc::invalid);
    }

    void rethrow()
    {
        if (handlers_ && handlers_->caught) {
            std::exception_ptr caught = std::move(handlers_->caught);
            handlers_->caught = nullptr;
            std::rethrow_exception(caught);
        }
    }

    void reset() noexcept
    {
        if (session_) {
            ps_embed_close(session_);
            session_ = nullptr;
        }
    }

    ps_session_t *session_ = nullptr;
    std::unique_ptr<io_handlers> handlers_;
};

inline preface read_preface(int fd, int timeout_ms)
{
    preface out;
    const int rc = ps_preface_read(fd, out.session_id.data(), &out.subflow_id, timeout_ms);
    detail::check(rc);
    return out;
}

} // namespace parsock

namespace std {
template <>
struct is_error_code_enum<parsock::errc> : true_type {
};
} // namespace std

#endif
