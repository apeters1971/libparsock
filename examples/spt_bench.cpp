#include "parsock.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr std::size_t kChunk = 2 * 1024 * 1024;
constexpr std::size_t kFrame = 256 * 1024;
constexpr std::uint64_t kUntilEof = UINT64_MAX;
constexpr std::uint8_t kFlagPattern = 1;
constexpr char kMagic[4] = {'S', 'P', 'T', 'B'};

struct config {
    std::string cert;
    std::string key;
    std::string bind_host = "0.0.0.0";
    std::string host;
    std::uint16_t port = 8443;
    parsock::aead cipher = parsock::aead::aes_256_gcm;
    parsock::protection protection = parsock::protection::confidential;
    unsigned sockets = 4;
    unsigned workers = 0;
    std::uint64_t bytes = 0;
    double seconds = 0;
    std::string send_path;
    std::string recv_path;
    std::string csv_path;
    bool hash = false;
    bool chart = true;
    bool open_ended = false;
    std::uint64_t window = 512ull << 20;
    bool verify = true;
    std::vector<unsigned> socket_list;
    parsock::transport transport = parsock::transport::tcp;
    bool tcp_fallback = false;
    std::string rdma_device;
};

struct summary {
    std::string protection;
    std::string aead;
    unsigned sockets = 0;
    double seconds = 0;
    double tx_gbps = 0;
    double rx_gbps = 0;
    double tx_peak = 0;
    double rx_peak = 0;
    std::uint64_t tx_bytes = 0;
    std::uint64_t rx_bytes = 0;
    std::string tx_hash;
    std::string rx_hash;
};

struct meter {
    std::atomic<std::uint64_t> tx{0};
    std::atomic<std::uint64_t> rx{0};
    std::atomic<std::uint64_t> tx_expect{kUntilEof};
    std::atomic<std::uint64_t> rx_expect{kUntilEof};
    std::atomic<std::int64_t> tx_start_ns{0};
    std::atomic<std::int64_t> rx_start_ns{0};
    std::atomic<std::int64_t> tx_end_ns{0};
    std::atomic<std::int64_t> rx_end_ns{0};
    std::atomic<unsigned> sockets{0};
    std::atomic<std::uint32_t> rtt_us{0};
    std::atomic<std::uint32_t> frame_bytes{0};
    std::atomic<int> workers_left{2};
    std::atomic<bool> finished{false};
};

struct sample {
    double tx_gbps = 0;
    double rx_gbps = 0;
};

struct failure_slot {
    std::mutex mu;
    std::exception_ptr ep;
    void capture()
    {
        std::lock_guard<std::mutex> lock(mu);
        if (!ep)
            ep = std::current_exception();
    }
    void rethrow()
    {
        std::lock_guard<std::mutex> lock(mu);
        if (ep)
            std::rethrow_exception(ep);
    }
};

volatile sig_atomic_t g_stop = 0;

void restore_cursor()
{
    const char seq[] = "\033[?25h";
    if (write(STDOUT_FILENO, seq, sizeof(seq) - 1) < 0)
        return;
}

void on_signal(int)
{
    if (g_stop) {
        restore_cursor();
        const char nl[] = "\n";
        if (write(STDOUT_FILENO, nl, 1) < 0)
            return;
        _exit(130);
    }
    g_stop = 1;
}

std::int64_t now_ns()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void mark_start(std::atomic<std::int64_t> &slot)
{
    std::int64_t zero = 0;
    const std::int64_t stamp = now_ns();
    slot.compare_exchange_strong(zero, stamp);
}

const char *aead_name(parsock::aead algorithm)
{
    switch (algorithm) {
    case parsock::aead::aes_128_gcm:
        return "AES-128-GCM";
    case parsock::aead::aes_256_gcm:
        return "AES-256-GCM";
    case parsock::aead::chacha20_poly1305:
        return "ChaCha20-Poly1305";
    }
    return "AEAD";
}

const char *protection_name(parsock::protection profile)
{
    return profile == parsock::protection::authenticated ? "authenticated" : "confidential";
}

parsock::aead parse_aead(const std::string &text)
{
    if (text == "aes-128-gcm")
        return parsock::aead::aes_128_gcm;
    if (text == "aes-256-gcm")
        return parsock::aead::aes_256_gcm;
    if (text == "chacha20-poly1305")
        return parsock::aead::chacha20_poly1305;
    throw std::runtime_error("unknown aead: " + text);
}

parsock::protection parse_protection(const std::string &text)
{
    if (text == "confidential")
        return parsock::protection::confidential;
    if (text == "authenticated")
        return parsock::protection::authenticated;
    throw std::runtime_error("unknown protection: " + text);
}

const char *transport_name(parsock::transport value)
{
    if (value == parsock::transport::rdma)
        return "rdma";
    if (value == parsock::transport::automatic)
        return "auto";
    return "tcp";
}

parsock::transport parse_transport(const std::string &text)
{
    if (text == "tcp")
        return parsock::transport::tcp;
    if (text == "rdma")
        return parsock::transport::rdma;
    if (text == "auto")
        return parsock::transport::automatic;
    throw std::runtime_error("unknown transport: " + text);
}

std::uint64_t parse_size(const std::string &text)
{
    if (text.empty())
        throw std::runtime_error("empty size");
    std::size_t used = 0;
    unsigned long long value = std::stoull(text, &used, 10);
    if (used == 0)
        throw std::runtime_error("bad size: " + text);
    std::uint64_t scale = 1;
    if (used < text.size()) {
        const std::string suffix = text.substr(used);
        if (suffix == "K" || suffix == "k")
            scale = 1024ull;
        else if (suffix == "M" || suffix == "m")
            scale = 1024ull * 1024ull;
        else if (suffix == "G" || suffix == "g")
            scale = 1024ull * 1024ull * 1024ull;
        else if (suffix == "T" || suffix == "t")
            scale = 1024ull * 1024ull * 1024ull * 1024ull;
        else
            throw std::runtime_error("bad size suffix: " + text);
    }
    if (value > UINT64_MAX / scale)
        throw std::runtime_error("size overflow");
    return static_cast<std::uint64_t>(value) * scale;
}

std::uint16_t parse_port(const std::string &text)
{
    int value = std::stoi(text);
    if (value < 0 || value > 65535)
        throw std::runtime_error("bad port");
    return static_cast<std::uint16_t>(value);
}

std::vector<unsigned> parse_socket_list(const std::string &text)
{
    std::vector<unsigned> out;
    std::size_t begin = 0;
    while (begin < text.size()) {
        std::size_t comma = text.find(',', begin);
        if (comma == std::string::npos)
            comma = text.size();
        int value = std::stoi(text.substr(begin, comma - begin));
        if (value < 1 || value > PS_MAX_SUBFLOWS)
            throw std::runtime_error("sockets must be 1..64");
        out.push_back(static_cast<unsigned>(value));
        begin = comma + 1;
    }
    if (out.empty())
        throw std::runtime_error("empty socket list");
    return out;
}

std::string need_value(int &index, int argc, char **argv, const char *flag)
{
    if (index + 1 >= argc)
        throw std::runtime_error(std::string("missing value for ") + flag);
    return argv[++index];
}

void usage()
{
    std::cerr
        << "usage:\n"
        << "  spt_bench server [--cert CERT --key KEY] [--bind HOST] [--port N]\n"
        << "      [--aead aes-128-gcm|aes-256-gcm|chacha20-poly1305]\n"
        << "      [--sockets N] [--workers N] [--protection confidential|authenticated]\n"
        << "      [--transport tcp|rdma|auto] [--tcp-fallback] [--rdma-device NAME]\n"
        << "      [--send FILE] [--recv FILE] [--bytes SIZE] [--seconds SEC]\n"
        << "      [--window SIZE] [--no-verify] [--hash] [--csv FILE] [--no-chart]\n"
        << "  spt_bench client HOST PORT [--cert CERT --key KEY] [same options]\n"
        << "  spt_bench suite --cert CERT --key KEY [--bytes SIZE] [--sockets 1,4,8]\n"
        << "      [--workers N] [--seconds SEC] [--csv FILE] [--no-chart]\n"
        << "\n"
        << "Authenticated mode leaves the payload in plaintext and still MACs every record.\n"
        << "Both endpoints must pass --protection authenticated. A short preamble stays\n"
        << "confidential. Sizes accept K, M, G, and T as powers of 1024.\n"
        << "Omit --bytes, --seconds, and --send to receive only. --seconds alone sends\n"
        << "generated data until the timer. A client with none of those, and no --recv,\n"
        << "sends generated data until Ctrl-C. Ctrl-C ends the transmit cleanly; a second\n"
        << "Ctrl-C exits immediately.\n"
        << "The server always has a certificate. Without --cert and --key it writes a\n"
        << "self-signed one. A client certificate is optional; without one, the client\n"
        << "still encrypts to the server certificate and does not present its own.\n";
}

config parse_args(int argc, char **argv, std::vector<std::string> &positionals)
{
    config cfg;
    for (int i = 2; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "--cert")
            cfg.cert = need_value(i, argc, argv, "--cert");
        else if (arg == "--key")
            cfg.key = need_value(i, argc, argv, "--key");
        else if (arg == "--bind")
            cfg.bind_host = need_value(i, argc, argv, "--bind");
        else if (arg == "--port")
            cfg.port = parse_port(need_value(i, argc, argv, "--port"));
        else if (arg == "--aead")
            cfg.cipher = parse_aead(need_value(i, argc, argv, "--aead"));
        else if (arg == "--sockets")
            cfg.socket_list = parse_socket_list(need_value(i, argc, argv, "--sockets"));
        else if (arg == "--workers")
            cfg.workers = static_cast<unsigned>(std::stoul(need_value(i, argc, argv, "--workers")));
        else if (arg == "--protection")
            cfg.protection = parse_protection(need_value(i, argc, argv, "--protection"));
        else if (arg == "--transport")
            cfg.transport = parse_transport(need_value(i, argc, argv, "--transport"));
        else if (arg == "--tcp-fallback")
            cfg.tcp_fallback = true;
        else if (arg == "--rdma-device")
            cfg.rdma_device = need_value(i, argc, argv, "--rdma-device");
        else if (arg == "--send")
            cfg.send_path = need_value(i, argc, argv, "--send");
        else if (arg == "--recv")
            cfg.recv_path = need_value(i, argc, argv, "--recv");
        else if (arg == "--bytes")
            cfg.bytes = parse_size(need_value(i, argc, argv, "--bytes"));
        else if (arg == "--seconds")
            cfg.seconds = std::stod(need_value(i, argc, argv, "--seconds"));
        else if (arg == "--csv")
            cfg.csv_path = need_value(i, argc, argv, "--csv");
        else if (arg == "--window")
            cfg.window = parse_size(need_value(i, argc, argv, "--window"));
        else if (arg == "--no-verify")
            cfg.verify = false;
        else if (arg == "--hash")
            cfg.hash = true;
        else if (arg == "--no-chart")
            cfg.chart = false;
        else if (arg == "--help" || arg == "-h")
            throw std::runtime_error("help");
        else if (!arg.empty() && arg[0] == '-')
            throw std::runtime_error("unknown option: " + arg);
        else
            positionals.push_back(arg);
    }
    if (!cfg.socket_list.empty())
        cfg.sockets = cfg.socket_list.front();
    if (cfg.workers > 16)
        throw std::runtime_error("workers must be 0..16");
    if (!cfg.send_path.empty() && cfg.bytes != 0)
        throw std::runtime_error("--send and --bytes are alternatives");
    return cfg;
}

void require_tls(const config &cfg)
{
    if (cfg.cert.empty() || cfg.key.empty())
        throw std::runtime_error("--cert and --key are required");
}

[[noreturn]] void tls_fail(const char *what)
{
    char buf[256] = {};
    const unsigned long err = ERR_get_error();
    if (err != 0)
        ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(std::string(what) + (buf[0] ? std::string(": ") + buf : std::string()));
}

bool is_wildcard_bind(const std::string &host)
{
    return host.empty() || host == "0.0.0.0" || host == "::" || host == "*";
}

bool is_ip_literal(const std::string &host)
{
    unsigned char buf[16];
    return inet_pton(AF_INET, host.c_str(), buf) == 1 || inet_pton(AF_INET6, host.c_str(), buf) == 1;
}

void add_unique(std::vector<std::string> &names, const std::string &entry)
{
    if (std::find(names.begin(), names.end(), entry) == names.end())
        names.push_back(entry);
}

std::string certificate_names(const std::string &bind_host)
{
    std::vector<std::string> names;
    add_unique(names, "DNS:localhost");
    add_unique(names, "IP:127.0.0.1");
    add_unique(names, "IP:::1");
    char host[256];
    if (gethostname(host, sizeof(host)) == 0) {
        host[sizeof(host) - 1] = '\0';
        if (host[0] != '\0' && std::strcmp(host, "localhost") != 0)
            add_unique(names, std::string("DNS:") + host);
    }
    if (!is_wildcard_bind(bind_host))
        add_unique(names, (is_ip_literal(bind_host) ? "IP:" : "DNS:") + bind_host);
    struct ifaddrs *list = nullptr;
    if (getifaddrs(&list) == 0) {
        for (struct ifaddrs *ifa = list; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr)
                continue;
            char text[INET6_ADDRSTRLEN];
            if (ifa->ifa_addr->sa_family == AF_INET) {
                const auto *addr = reinterpret_cast<const struct sockaddr_in *>(ifa->ifa_addr);
                if (inet_ntop(AF_INET, &addr->sin_addr, text, sizeof(text)) != nullptr)
                    add_unique(names, std::string("IP:") + text);
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                const auto *addr = reinterpret_cast<const struct sockaddr_in6 *>(ifa->ifa_addr);
                if (inet_ntop(AF_INET6, &addr->sin6_addr, text, sizeof(text)) != nullptr)
                    add_unique(names, std::string("IP:") + text);
            }
        }
        freeifaddrs(list);
    }
    std::string joined;
    for (const std::string &name : names) {
        if (!joined.empty())
            joined += ',';
        joined += name;
    }
    return joined;
}

struct ephemeral_cert {
    std::filesystem::path cert;
    std::filesystem::path key;

    ephemeral_cert() = default;
    ephemeral_cert(const ephemeral_cert &) = delete;
    ephemeral_cert &operator=(const ephemeral_cert &) = delete;
    ephemeral_cert(ephemeral_cert &&other) noexcept : cert(std::move(other.cert)), key(std::move(other.key))
    {
        other.cert.clear();
        other.key.clear();
    }
    ephemeral_cert &operator=(ephemeral_cert &&other) noexcept
    {
        if (this != &other) {
            remove();
            cert = std::move(other.cert);
            key = std::move(other.key);
            other.cert.clear();
            other.key.clear();
        }
        return *this;
    }
    ~ephemeral_cert() { remove(); }

    void remove() noexcept
    {
        std::error_code ec;
        if (!cert.empty())
            std::filesystem::remove(cert, ec);
        if (!key.empty())
            std::filesystem::remove(key, ec);
    }
};

ephemeral_cert make_ephemeral_cert(const std::string &bind_host)
{
    const auto dir = std::filesystem::temp_directory_path();
    const std::string stamp = std::to_string(static_cast<long long>(getpid()));
    ephemeral_cert files;
    files.cert = dir / ("spt-bench-" + stamp + "-cert.pem");
    files.key = dir / ("spt-bench-" + stamp + "-key.pem");

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                                                                     EVP_PKEY_CTX_free);
    EVP_PKEY *raw_key = nullptr;
    if (!kctx || EVP_PKEY_keygen_init(kctx.get()) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx.get(), 2048) != 1 ||
        EVP_PKEY_keygen(kctx.get(), &raw_key) != 1)
        tls_fail("certificate key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);

    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    if (!cert)
        tls_fail("certificate");
    if (X509_set_version(cert.get(), 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60 * 24 * 365) == nullptr ||
        X509_set_pubkey(cert.get(), key.get()) != 1)
        tls_fail("certificate");
    X509_NAME *name = X509_get_subject_name(cert.get());
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("localhost"), -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert.get(), name) != 1)
        tls_fail("certificate name");

    const std::string names = certificate_names(bind_host);
    X509V3_CTX ext;
    X509V3_set_ctx_nodb(&ext);
    X509V3_set_ctx(&ext, cert.get(), cert.get(), nullptr, nullptr, 0);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san(
        X509V3_EXT_conf_nid(nullptr, &ext, NID_subject_alt_name, names.c_str()), X509_EXTENSION_free);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> basic(
        X509V3_EXT_conf_nid(nullptr, &ext, NID_basic_constraints, "critical,CA:TRUE"), X509_EXTENSION_free);
    if (!san || !basic || X509_add_ext(cert.get(), basic.get(), -1) != 1 ||
        X509_add_ext(cert.get(), san.get(), -1) != 1 || X509_sign(cert.get(), key.get(), EVP_sha256()) == 0)
        tls_fail("certificate extensions");

    std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new_file(files.cert.c_str(), "w"), BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new_file(files.key.c_str(), "w"), BIO_free);
    if (!cert_bio || !key_bio || PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1 ||
        PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
        tls_fail("writing certificate");
    cert_bio.reset();
    key_bio.reset();
    chmod(files.key.c_str(), S_IRUSR | S_IWUSR);

    std::cerr << "generated self-signed certificate\n"
              << "  cert " << files.cert.string() << "\n"
              << "  key  " << files.key.string() << "\n";
    return files;
}

enum class tls_use { mutual, server, client };

parsock::options make_options(const config &cfg, const std::string &server_name, tls_use use = tls_use::mutual)
{
    parsock::options opt;
    if (use == tls_use::client && cfg.cert.empty() && cfg.key.empty()) {
        opt.verify_peer(false).allow_insecure(true);
    } else if (use == tls_use::server) {
        opt.certificate(cfg.cert).private_key(cfg.key).verify_peer(false);
    } else {
        opt.certificate(cfg.cert).private_key(cfg.key).ca_file(cfg.cert).verify_peer(true);
    }
    opt.sockets(cfg.sockets)
        .workers(cfg.workers)
        .cipher(cfg.cipher)
        .minimum_protection(cfg.protection)
        .frame_size(kFrame)
        .receive_window(cfg.window)
        .connect_timeout(10000)
        .io_timeout(300000)
        .transport(cfg.transport);
    if (cfg.tcp_fallback)
        opt.tcp_fallback(true);
    if (!cfg.rdma_device.empty())
        opt.rdma_device(cfg.rdma_device);
    if (!server_name.empty())
        opt.server_name(server_name);
    return opt;
}

void put_u64(std::uint8_t *out, std::uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<std::uint8_t>(value & 0xffu);
        value >>= 8;
    }
}

std::uint64_t get_u64(const std::uint8_t *in)
{
    std::uint64_t value = 0;
    for (int i = 0; i < 8; i++)
        value = (value << 8) | in[i];
    return value;
}

inline std::uint8_t pattern_byte(std::uint64_t offset)
{
    return static_cast<std::uint8_t>((offset * 131u) ^ (offset >> 8));
}

struct pattern_table {
    alignas(64) std::uint8_t bytes[65536 * 2];
    pattern_table()
    {
        for (std::size_t i = 0; i < sizeof(bytes); i++)
            bytes[i] = pattern_byte(i);
    }
};

const pattern_table &global_pattern()
{
    static const pattern_table table;
    return table;
}

void fill_pattern(std::uint8_t *dst, std::uint64_t offset, std::size_t n)
{
    const auto &table = global_pattern();
    std::size_t done = 0;
    while (done < n) {
        const std::size_t phase = static_cast<std::size_t>((offset + done) & 0xffffu);
        std::size_t step = 65536;
        if (step > n - done)
            step = n - done;
        std::memcpy(dst + done, table.bytes + phase, step);
        done += step;
    }
}

bool pattern_matches(const std::uint8_t *src, std::uint64_t offset, std::size_t n)
{
    const auto &table = global_pattern();
    std::size_t done = 0;
    while (done < n) {
        const std::size_t phase = static_cast<std::size_t>((offset + done) & 0xffffu);
        std::size_t step = 65536;
        if (step > n - done)
            step = n - done;
        if (std::memcmp(src + done, table.bytes + phase, step) != 0)
            return false;
        done += step;
    }
    return true;
}

class hasher {
public:
    explicit hasher(bool enabled) : enabled_(enabled)
    {
        if (!enabled_)
            return;
        ctx_ = EVP_MD_CTX_new();
        if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("sha256 init failed");
    }
    hasher(const hasher &) = delete;
    hasher &operator=(const hasher &) = delete;
    ~hasher() { EVP_MD_CTX_free(ctx_); }

    void update(const void *data, std::size_t length)
    {
        if (!enabled_ || length == 0)
            return;
        if (EVP_DigestUpdate(ctx_, data, length) != 1)
            throw std::runtime_error("sha256 update failed");
    }

    std::string hex()
    {
        if (!enabled_)
            return {};
        unsigned char digest[32];
        unsigned int length = 0;
        if (EVP_DigestFinal_ex(ctx_, digest, &length) != 1 || length != 32)
            throw std::runtime_error("sha256 final failed");
        enabled_ = false;
        static const char *digits = "0123456789abcdef";
        std::string out(64, '0');
        for (unsigned int i = 0; i < 32; i++) {
            out[i * 2] = digits[digest[i] >> 4];
            out[i * 2 + 1] = digits[digest[i] & 0xf];
        }
        return out;
    }

private:
    bool enabled_ = false;
    EVP_MD_CTX *ctx_ = nullptr;
};

std::uint64_t file_size(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot read " + path);
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0)
        throw std::runtime_error("cannot size " + path);
    return static_cast<std::uint64_t>(size);
}

void read_exact(std::istream &in, char *data, std::size_t length, const std::string &path)
{
    in.read(data, static_cast<std::streamsize>(length));
    if (in.gcount() != static_cast<std::streamsize>(length))
        throw std::runtime_error("short read from " + path);
}

std::size_t read_full(parsock::connection &conn, std::uint8_t *data, std::size_t length)
{
    std::size_t got = 0;
    while (got < length) {
        const std::size_t n = conn.recv(data + got, length - got);
        if (n == 0)
            break;
        got += n;
    }
    return got;
}

void send_direction(parsock::connection &conn, const config &cfg, meter &stats, hasher &hash,
                    failure_slot &errors)
{
    try {
        const bool from_file = !cfg.send_path.empty();
        const bool timed = cfg.seconds > 0;
        const bool open = cfg.open_ended || (timed && !from_file && cfg.bytes == 0);
        std::uint64_t planned = 0;
        std::ifstream file;
        if (from_file) {
            planned = file_size(cfg.send_path);
            file.open(cfg.send_path, std::ios::binary);
            if (!file)
                throw std::runtime_error("cannot read " + cfg.send_path);
        } else if (cfg.bytes > 0) {
            planned = cfg.bytes;
        } else if (open) {
            planned = kUntilEof;
        }
        const bool generated = !from_file && planned > 0;
        const bool known_length = planned != kUntilEof && !timed;
        const std::uint64_t announced = known_length ? planned : (planned == 0 ? 0 : kUntilEof);
        if (known_length)
            stats.tx_expect.store(planned);

        std::uint8_t header[20];
        std::memcpy(header, kMagic, 4);
        put_u64(header + 4, announced);
        header[12] = (generated && cfg.verify) ? kFlagPattern : 0;
        std::memset(header + 13, 0, 7);
        conn.send(header, sizeof(header), parsock::protection::confidential);

        std::vector<std::uint8_t> buf(kChunk);
        if (!from_file && cfg.verify)
            fill_pattern(buf.data(), 0, buf.size());
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                  std::chrono::duration<double>(cfg.seconds));
        std::uint64_t sent = 0;
        while (sent < planned && !g_stop) {
            if (timed && std::chrono::steady_clock::now() >= deadline)
                break;
            std::size_t chunk = kChunk;
            if (static_cast<std::uint64_t>(chunk) > planned - sent)
                chunk = static_cast<std::size_t>(planned - sent);
            if (from_file)
                read_exact(file, reinterpret_cast<char *>(buf.data()), chunk, cfg.send_path);
            else if (cfg.verify && (sent & 0xffffu) != 0) {
                fill_pattern(buf.data(), sent, chunk);
            }
            mark_start(stats.tx_start_ns);
            conn.send(buf.data(), chunk, cfg.protection);
            hash.update(buf.data(), chunk);
            sent += chunk;
            stats.tx.fetch_add(chunk);
        }
        stats.tx_end_ns.store(sent == 0 ? stats.tx_start_ns.load() : now_ns());
        conn.shutdown_write();
    } catch (...) {
        try {
            conn.shutdown_write();
        } catch (...) {
        }
        errors.capture();
    }
    if (stats.workers_left.fetch_sub(1) == 1)
        stats.finished.store(true);
}

void recv_direction(parsock::connection &conn, const config &cfg, meter &stats, hasher &hash,
                    failure_slot &errors)
{
    try {
        std::uint8_t header[20];
        if (read_full(conn, header, sizeof(header)) != sizeof(header))
            throw std::runtime_error("missing stream preamble");
        if (std::memcmp(header, kMagic, 4) != 0)
            throw std::runtime_error("unexpected stream preamble");
        const std::uint64_t announced = get_u64(header + 4);
        const bool check_pattern = cfg.verify && ((header[12] & kFlagPattern) != 0);
        if (announced != kUntilEof)
            stats.rx_expect.store(announced);

        std::ofstream file;
        if (!cfg.recv_path.empty()) {
            file.open(cfg.recv_path, std::ios::binary | std::ios::trunc);
            if (!file)
                throw std::runtime_error("cannot write " + cfg.recv_path);
        }
        std::vector<std::uint8_t> buf(kChunk);
        std::uint64_t got = 0;
        const std::uint64_t target = announced == kUntilEof ? kUntilEof : announced;
        while (got < target) {
            std::size_t want = buf.size();
            if (target != kUntilEof && target - got < want)
                want = static_cast<std::size_t>(target - got);
            const std::size_t n = conn.recv(buf.data(), want);
            if (n == 0) {
                if (target != kUntilEof)
                    throw std::runtime_error("stream ended before the announced length");
                break;
            }
            if (check_pattern && !pattern_matches(buf.data(), got, n))
                throw std::runtime_error("payload mismatch");
            if (!cfg.recv_path.empty()) {
                file.write(reinterpret_cast<const char *>(buf.data()), static_cast<std::streamsize>(n));
                if (!file)
                    throw std::runtime_error("write failed: " + cfg.recv_path);
            }
            mark_start(stats.rx_start_ns);
            hash.update(buf.data(), n);
            got += n;
            stats.rx.fetch_add(n);
        }
        if (target != kUntilEof && got >= target) {
            std::uint8_t extra = 0;
            if (conn.recv(&extra, 1) > 0)
                throw std::runtime_error("trailing bytes after payload");
        }
        stats.rx_end_ns.store(got == 0 ? stats.rx_start_ns.load() : now_ns());
        if (!cfg.recv_path.empty())
            file.close();
    } catch (...) {
        errors.capture();
    }
    if (stats.workers_left.fetch_sub(1) == 1)
        stats.finished.store(true);
}

int terminal_columns()
{
    winsize size{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col >= 20)
        return size.ws_col;
    return 80;
}

std::string sparkline(const std::vector<sample> &history, bool transmit, int width)
{
    static const char *blocks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    const int count = width < 60 ? width : 60;
    double peak = 0;
    const int begin = static_cast<int>(history.size()) > count
                          ? static_cast<int>(history.size()) - count
                          : 0;
    for (int i = begin; i < static_cast<int>(history.size()); i++) {
        const double value = transmit ? history[static_cast<std::size_t>(i)].tx_gbps
                                      : history[static_cast<std::size_t>(i)].rx_gbps;
        if (value > peak)
            peak = value;
    }
    std::string line;
    const int pad = count - (static_cast<int>(history.size()) - begin);
    for (int i = 0; i < pad; i++)
        line += blocks[0];
    for (int i = begin; i < static_cast<int>(history.size()); i++) {
        const double value = transmit ? history[static_cast<std::size_t>(i)].tx_gbps
                                      : history[static_cast<std::size_t>(i)].rx_gbps;
        int level = 0;
        if (peak > 0)
            level = static_cast<int>(value / peak * 7.0 + 0.5);
        if (level < 0)
            level = 0;
        if (level > 7)
            level = 7;
        line += blocks[level];
    }
    return line;
}

std::string rate_text(double gbps)
{
    std::ostringstream out;
    out << std::fixed << std::setprecision(gbps >= 10 ? 1 : 2) << gbps << " Gb/s";
    return out.str();
}

std::string bytes_text(std::uint64_t bytes)
{
    const char *unit = "B";
    double value = static_cast<double>(bytes);
    if (bytes >= 1000000000ull) {
        value /= 1e9;
        unit = "GB";
    } else if (bytes >= 1000000ull) {
        value /= 1e6;
        unit = "MB";
    } else if (bytes >= 1000ull) {
        value /= 1e3;
        unit = "KB";
    }
    std::ostringstream out;
    out << std::fixed << std::setprecision(value >= 100 || unit[0] == 'B' ? 0 : 2) << value << " " << unit;
    return out.str();
}

double gbps_of(std::uint64_t bytes, std::int64_t start_ns, std::int64_t end_ns)
{
    if (start_ns == 0 || end_ns <= start_ns || bytes == 0)
        return 0;
    const double seconds = static_cast<double>(end_ns - start_ns) / 1e9;
    return (static_cast<double>(bytes) * 8.0) / seconds / 1e9;
}

struct chart {
    bool enabled = false;
    int lines = 0;
    std::vector<sample> history;
    double tx_peak = 0;
    double rx_peak = 0;

    explicit chart(bool on) : enabled(on)
    {
        if (enabled)
            std::fputs("\033[?25l", stdout);
    }
    chart(const chart &) = delete;
    chart &operator=(const chart &) = delete;
    ~chart()
    {
        if (enabled) {
            std::fputs("\033[?25h\n", stdout);
            std::fflush(stdout);
        }
    }

    void draw(const meter &stats, const config &cfg, const std::string &title)
    {
        if (!enabled)
            return;
        if (lines > 0)
            std::cout << "\033[" << lines << "A";
        const std::uint64_t tx = stats.tx.load();
        const std::uint64_t rx = stats.rx.load();
        const std::uint64_t tx_expect = stats.tx_expect.load();
        const std::uint64_t rx_expect = stats.rx_expect.load();
        const unsigned frame = stats.frame_bytes.load() ? stats.frame_bytes.load() : kFrame;
        std::cout << title << "   " << aead_name(cfg.cipher) << "   " << protection_name(cfg.protection)
                  << "   " << stats.sockets.load() << " sockets   frame " << (frame / 1024)
                  << " KiB   workers " << cfg.workers << "   RTT " << stats.rtt_us.load()
                  << " us\033[K\n";
        std::cout << "tx   " << rate_text(history.empty() ? 0 : history.back().tx_gbps) << "   avg "
                  << rate_text(gbps_of(tx, stats.tx_start_ns.load(), now_ns())) << "   peak "
                  << rate_text(tx_peak) << "    " << bytes_text(tx);
        if (tx_expect != kUntilEof && tx_expect > 0)
            std::cout << " / " << bytes_text(tx_expect);
        std::cout << "\033[K\n     " << sparkline(history, true, terminal_columns() - 5) << "\033[K\n";
        std::cout << "rx   " << rate_text(history.empty() ? 0 : history.back().rx_gbps) << "   avg "
                  << rate_text(gbps_of(rx, stats.rx_start_ns.load(), now_ns())) << "   peak "
                  << rate_text(rx_peak) << "    " << bytes_text(rx);
        if (rx_expect != kUntilEof && rx_expect > 0)
            std::cout << " / " << bytes_text(rx_expect);
        std::cout << "\033[K\n     " << sparkline(history, false, terminal_columns() - 5) << "\033[K\n";
        std::cout.flush();
        lines = 5;
    }
};

void write_csv_row(std::ostream &out, double elapsed, const sample &point, std::uint64_t tx,
                   std::uint64_t rx, unsigned sockets, std::uint32_t rtt, const config &cfg)
{
    out << std::fixed << std::setprecision(3) << elapsed << ',' << std::setprecision(4) << point.tx_gbps
        << ',' << point.rx_gbps << ',' << tx << ',' << rx << ',' << sockets << ',' << rtt << ','
        << protection_name(cfg.protection) << ',' << aead_name(cfg.cipher) << ',' << cfg.sockets << '\n';
    out.flush();
}

void sample_loop(parsock::connection &conn, meter &stats, const config &cfg, const std::string &title,
                 bool interval_stdout, std::ofstream *csv, chart &panel, summary &out)
{
    const auto origin = std::chrono::steady_clock::now();
    auto previous = origin;
    std::uint64_t prev_tx = 0;
    std::uint64_t prev_rx = 0;
    while (!stats.finished.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const auto current = std::chrono::steady_clock::now();
        if (current - previous < std::chrono::milliseconds(250) && !stats.finished.load())
            continue;
        try {
            const parsock::stats live = conn.statistics();
            stats.sockets.store(live.active_sockets);
            stats.rtt_us.store(live.rtt_us);
            stats.frame_bytes.store(live.frame_bytes);
        } catch (...) {
        }
        const std::uint64_t tx = stats.tx.load();
        const std::uint64_t rx = stats.rx.load();
        const double dt = std::chrono::duration<double>(current - previous).count();
        sample point;
        if (dt > 0) {
            point.tx_gbps = (static_cast<double>(tx - prev_tx) * 8.0) / dt / 1e9;
            point.rx_gbps = (static_cast<double>(rx - prev_rx) * 8.0) / dt / 1e9;
        }
        if (point.tx_gbps > panel.tx_peak)
            panel.tx_peak = point.tx_gbps;
        if (point.rx_gbps > panel.rx_peak)
            panel.rx_peak = point.rx_gbps;
        panel.history.push_back(point);
        const double elapsed = std::chrono::duration<double>(current - origin).count();
        if (csv)
            write_csv_row(*csv, elapsed, point, tx, rx, stats.sockets.load(), stats.rtt_us.load(), cfg);
        if (interval_stdout)
            write_csv_row(std::cout, elapsed, point, tx, rx, stats.sockets.load(), stats.rtt_us.load(), cfg);
        panel.draw(stats, cfg, title);
        previous = current;
        prev_tx = tx;
        prev_rx = rx;
    }
    out.tx_peak = panel.tx_peak;
    out.rx_peak = panel.rx_peak;
}

summary run_transfer(parsock::connection &conn, const config &cfg, const std::string &title, bool chart_on,
                     bool interval_stdout, std::ofstream *csv)
{
    meter stats;
    hasher tx_hash(cfg.hash);
    hasher rx_hash(cfg.hash);
    failure_slot errors;
    chart panel(chart_on && isatty(STDOUT_FILENO) == 1);
    summary result;
    result.protection = protection_name(cfg.protection);
    result.aead = aead_name(cfg.cipher);
    result.sockets = cfg.sockets;

    std::thread receiver(recv_direction, std::ref(conn), std::cref(cfg), std::ref(stats), std::ref(rx_hash),
                         std::ref(errors));
    std::thread sender(send_direction, std::ref(conn), std::cref(cfg), std::ref(stats), std::ref(tx_hash),
                       std::ref(errors));
    sample_loop(conn, stats, cfg, title, interval_stdout, csv, panel, result);
    sender.join();
    receiver.join();

    result.tx_bytes = stats.tx.load();
    result.rx_bytes = stats.rx.load();
    result.tx_gbps = gbps_of(result.tx_bytes, stats.tx_start_ns.load(), stats.tx_end_ns.load());
    result.rx_gbps = gbps_of(result.rx_bytes, stats.rx_start_ns.load(), stats.rx_end_ns.load());
    if (result.tx_gbps > result.tx_peak)
        result.tx_peak = result.tx_gbps;
    if (result.rx_gbps > result.rx_peak)
        result.rx_peak = result.rx_gbps;
    const std::int64_t start = stats.tx_start_ns.load() ? stats.tx_start_ns.load() : stats.rx_start_ns.load();
    const std::int64_t end = std::max(stats.tx_end_ns.load(), stats.rx_end_ns.load());
    if (start && end > start)
        result.seconds = static_cast<double>(end - start) / 1e9;
    if (cfg.hash) {
        result.tx_hash = tx_hash.hex();
        result.rx_hash = rx_hash.hex();
    }
    errors.rethrow();
    return result;
}

void print_summary(const summary &result)
{
    std::cout << std::fixed << std::setprecision(result.seconds >= 10 ? 2 : 3);
    std::cout << "tx  " << rate_text(result.tx_gbps) << "   peak " << rate_text(result.tx_peak) << "   "
              << bytes_text(result.tx_bytes) << "   " << result.seconds << " s\n";
    std::cout << "rx  " << rate_text(result.rx_gbps) << "   peak " << rate_text(result.rx_peak) << "   "
              << bytes_text(result.rx_bytes) << "\n";
    if (!result.tx_hash.empty())
        std::cout << "sha256 tx " << result.tx_hash << "\n";
    if (!result.rx_hash.empty())
        std::cout << "sha256 rx " << result.rx_hash << "\n";
}

std::string endpoint_title(const std::string &host, std::uint16_t port)
{
    return "SPT  " + host + ":" + std::to_string(port);
}

int kernel_buffer(int reported)
{
    if (reported < 0)
        return reported;
#if defined(__linux__)
    /* getsockopt(SO_SNDBUF/SO_RCVBUF) returns twice the size the kernel kept. */
    return reported / 2;
#else
    return reported;
#endif
}

bool same_tcp(const ps_tcp_setting &a, const ps_tcp_setting &b)
{
    return a.data == b.data && a.nodelay == b.nodelay && a.nonblock == b.nonblock && a.sndbuf == b.sndbuf &&
           a.rcvbuf == b.rcvbuf && a.mss == b.mss;
}

void print_tcp_settings(parsock::connection &conn)
{
    ps_tcp_setting items[PS_MAX_SUBFLOWS + 1];
    const int n = ps_connection_tcp_settings(conn.native(), items, PS_MAX_SUBFLOWS + 1);
    if (n <= 0) {
        std::cerr << "tcp  settings unavailable\n";
        return;
    }
    std::cerr << "tcp  SO_SNDBUF and SO_RCVBUF are the sizes the kernel kept";
#if defined(__linux__)
    std::cerr << "; getsockopt reports twice that";
#endif
    std::cerr << "\n";
    for (int i = 0; i < n;) {
        int count = 1;
        while (i + count < n && same_tcp(items[i], items[i + count]))
            count++;
        const ps_tcp_setting &item = items[i];
        std::cerr << "tcp  " << (item.data ? "data" : "control");
        if (item.data)
            std::cerr << " x" << count;
        std::cerr << "  TCP_NODELAY " << item.nodelay << "  nonblock " << item.nonblock << "  SO_SNDBUF "
                  << kernel_buffer(item.sndbuf) << "  SO_RCVBUF " << kernel_buffer(item.rcvbuf) << "  MSS "
                  << item.mss << "\n";
        i += count;
    }
}

int run_endpoint(config cfg, bool server, const std::vector<std::string> &positionals)
{
    if (server)
        require_tls(cfg);
    else if (cfg.cert.empty() != cfg.key.empty())
        throw std::runtime_error("client --cert and --key must be set together");
    if (cfg.socket_list.size() > 1)
        throw std::runtime_error("a socket list belongs on spt_bench suite");
    std::ofstream csv;
    if (!cfg.csv_path.empty()) {
        csv.open(cfg.csv_path);
        if (!csv)
            throw std::runtime_error("cannot write " + cfg.csv_path);
        csv << "elapsed_s,tx_gbps,rx_gbps,tx_bytes,rx_bytes,sockets,rtt_us,protection,aead,configured_sockets\n";
    }
    const bool tty = isatty(STDOUT_FILENO) == 1;
    const bool chart_on = cfg.chart && tty;
    const bool interval_stdout = !tty && cfg.csv_path.empty();
    if (interval_stdout)
        std::cout << "elapsed_s,tx_gbps,rx_gbps,tx_bytes,rx_bytes,sockets,rtt_us,protection,aead,configured_sockets\n";

    if (!server && cfg.send_path.empty() && cfg.bytes == 0 && cfg.seconds <= 0 && cfg.recv_path.empty())
        cfg.open_ended = true;

    if (cfg.transport == parsock::transport::rdma && ps_rdma_supported() == 0)
        throw std::runtime_error(
            "RDMA transport is not in this build. Install librdmacm-devel and libibverbs-devel, then reconfigure and rebuild.");

    if (server) {
        if (!positionals.empty())
            throw std::runtime_error("server takes no positional arguments");
        parsock::options opt = make_options(cfg, "", tls_use::server);
        parsock::listener listener = parsock::listener::listen(cfg.bind_host, cfg.port, opt);
        const parsock::endpoints ports = listener.ports();
        std::cerr << "listening " << cfg.bind_host << ":" << ports.control << "  " << aead_name(cfg.cipher)
                  << "  " << protection_name(cfg.protection) << "  sockets " << cfg.sockets;
        if (cfg.transport != parsock::transport::tcp)
            std::cerr << "  transport " << transport_name(cfg.transport);
        std::cerr << std::endl;
        parsock::connection conn = listener.accept();
        if (cfg.transport != parsock::transport::tcp)
            std::cerr << "negotiated transport " << transport_name(conn.transport()) << std::endl;
        print_tcp_settings(conn);
        const summary result = run_transfer(conn, cfg, endpoint_title(cfg.bind_host, ports.control), chart_on,
                                             interval_stdout, csv.is_open() ? &csv : nullptr);
        print_summary(result);
        return 0;
    }

    if (positionals.size() != 2)
        throw std::runtime_error("client requires HOST PORT");
    cfg.host = positionals[0];
    cfg.port = parse_port(positionals[1]);
    parsock::options opt = make_options(cfg, cfg.host, tls_use::client);
    parsock::connection conn = parsock::connection::connect(cfg.host, cfg.port, opt);
    if (cfg.transport != parsock::transport::tcp)
        std::cerr << "negotiated transport " << transport_name(conn.transport()) << std::endl;
    print_tcp_settings(conn);
    const summary result = run_transfer(conn, cfg, endpoint_title(cfg.host, cfg.port), chart_on, interval_stdout,
                                         csv.is_open() ? &csv : nullptr);
    print_summary(result);
    return 0;
}

std::vector<summary> suite_cases(const config &base)
{
    const std::vector<unsigned> sockets = base.socket_list.empty()
                                               ? std::vector<unsigned>{1u, 4u, 8u}
                                               : base.socket_list;
    const parsock::aead ciphers[] = {parsock::aead::aes_128_gcm, parsock::aead::aes_256_gcm,
                                     parsock::aead::chacha20_poly1305};
    std::vector<summary> rows;
    config cfg = base;
    if (cfg.bytes == 0 && cfg.seconds <= 0)
        cfg.bytes = 256ull << 20;
    const bool tty = isatty(STDOUT_FILENO) == 1;
    const bool chart_on = cfg.chart && tty;
    std::ofstream csv;
    if (!cfg.csv_path.empty()) {
        csv.open(cfg.csv_path);
        if (!csv)
            throw std::runtime_error("cannot write " + cfg.csv_path);
        csv << "elapsed_s,tx_gbps,rx_gbps,tx_bytes,rx_bytes,sockets,rtt_us,protection,aead,configured_sockets\n";
    }
    for (parsock::protection profile : {parsock::protection::confidential, parsock::protection::authenticated}) {
        for (parsock::aead algorithm : ciphers) {
            if (profile == parsock::protection::authenticated && algorithm != parsock::aead::aes_256_gcm)
                continue;
            for (unsigned count : sockets) {
                cfg.protection = profile;
                cfg.cipher = algorithm;
                cfg.sockets = count;
                parsock::options opt = make_options(cfg, "127.0.0.1");
                parsock::listener listener = parsock::listener::listen("127.0.0.1", 0, opt);
                const auto ports = listener.ports();
                failure_slot server_error;
                summary server_result;
                std::thread server([&] {
                    try {
                        parsock::connection conn = listener.accept();
                        config sink = cfg;
                        sink.send_path.clear();
                        sink.bytes = 0;
                        sink.seconds = 0;
                        sink.recv_path.clear();
                        server_result = run_transfer(conn, sink, "server", false, false, nullptr);
                    } catch (...) {
                        server_error.capture();
                    }
                });
                summary client_result;
                try {
                    parsock::connection conn = parsock::connection::connect("127.0.0.1", ports.control, opt);
                    client_result = run_transfer(conn, cfg, endpoint_title("127.0.0.1", ports.control), chart_on,
                                                  false, csv.is_open() ? &csv : nullptr);
                    print_summary(client_result);
                } catch (...) {
                    server.join();
                    throw;
                }
                server.join();
                server_error.rethrow();
                if (server_result.rx_bytes != client_result.tx_bytes)
                    throw std::runtime_error("server received a different byte count");
                rows.push_back(client_result);
            }
        }
    }
    return rows;
}

void print_table(const std::vector<summary> &rows)
{
    std::cout << "\nprotection       aead                  sockets   tx Gb/s    rx Gb/s    seconds\n";
    for (const summary &row : rows) {
        std::cout << std::left << std::setw(16) << row.protection << " " << std::setw(22) << row.aead
                  << std::right << std::setw(5) << row.sockets << "   " << std::fixed << std::setprecision(2)
                  << std::setw(8) << row.tx_gbps << "   " << std::setw(8) << row.rx_gbps << "   "
                  << std::setprecision(3) << std::setw(8) << row.seconds << "\n";
    }
}

std::string read_file(const std::filesystem::path &path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot read " + path.string());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path &path, const std::string &bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
        throw std::runtime_error("cannot write " + path.string());
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

int self_test(const std::vector<std::string> &positionals)
{
    if (positionals.size() != 2)
        throw std::runtime_error("self-test requires CERT KEY");
    config cfg;
    cfg.cert = positionals[0];
    cfg.key = positionals[1];
    cfg.bytes = 2ull << 20;
    cfg.sockets = 1;
    cfg.chart = false;
    cfg.hash = true;
    for (parsock::protection profile : {parsock::protection::confidential, parsock::protection::authenticated}) {
        cfg.protection = profile;
        cfg.cipher = parsock::aead::aes_256_gcm;
        parsock::options opt = make_options(cfg, "127.0.0.1");
        parsock::listener listener = parsock::listener::listen("127.0.0.1", 0, opt);
        const auto ports = listener.ports();
        failure_slot server_error;
        summary server_result;
        std::thread server([&] {
            try {
                parsock::connection conn = listener.accept();
                config sink = cfg;
                sink.bytes = 0;
                sink.hash = true;
                server_result = run_transfer(conn, sink, "server", false, false, nullptr);
            } catch (...) {
                server_error.capture();
            }
        });
        parsock::connection conn = parsock::connection::connect("127.0.0.1", ports.control, opt);
        const summary result = run_transfer(conn, cfg, "self-test", false, false, nullptr);
        server.join();
        server_error.rethrow();
        if (result.tx_bytes != cfg.bytes || server_result.rx_bytes != cfg.bytes ||
            result.tx_hash.empty() || result.tx_hash != server_result.rx_hash)
            throw std::runtime_error(std::string(protection_name(profile)) + " transfer mismatch");
    }

    const auto dir = std::filesystem::temp_directory_path();
    const auto send_a = dir / ("spt-bench-a-" + std::to_string(getpid()));
    const auto send_d = dir / ("spt-bench-d-" + std::to_string(getpid()));
    const auto recv_b = dir / ("spt-bench-b-" + std::to_string(getpid()));
    const auto recv_c = dir / ("spt-bench-c-" + std::to_string(getpid()));
    std::string bytes_a(200 * 1024, '\0');
    std::string bytes_d(180 * 1024, '\0');
    for (std::size_t i = 0; i < bytes_a.size(); i++)
        bytes_a[i] = static_cast<char>(i * 17 + 3);
    for (std::size_t i = 0; i < bytes_d.size(); i++)
        bytes_d[i] = static_cast<char>(i * 9 + 1);
    write_file(send_a, bytes_a);
    write_file(send_d, bytes_d);
    try {
        cfg.bytes = 0;
        cfg.hash = false;
        cfg.protection = parsock::protection::confidential;
        cfg.send_path = send_a.string();
        cfg.recv_path = recv_c.string();
        parsock::options opt = make_options(cfg, "127.0.0.1");
        parsock::listener listener = parsock::listener::listen("127.0.0.1", 0, opt);
        const auto ports = listener.ports();
        failure_slot server_error;
        std::thread server([&] {
            try {
                parsock::connection conn = listener.accept();
                config sink = cfg;
                sink.send_path = send_d.string();
                sink.recv_path = recv_b.string();
                (void)run_transfer(conn, sink, "server", false, false, nullptr);
            } catch (...) {
                server_error.capture();
            }
        });
        parsock::connection conn = parsock::connection::connect("127.0.0.1", ports.control, opt);
        (void)run_transfer(conn, cfg, "files", false, false, nullptr);
        server.join();
        server_error.rethrow();
        if (read_file(recv_b) != bytes_a || read_file(recv_c) != bytes_d)
            throw std::runtime_error("file round trip mismatch");
    } catch (...) {
        std::filesystem::remove(send_a);
        std::filesystem::remove(send_d);
        std::filesystem::remove(recv_b);
        std::filesystem::remove(recv_c);
        throw;
    }
    std::filesystem::remove(send_a);
    std::filesystem::remove(send_d);
    std::filesystem::remove(recv_b);
    std::filesystem::remove(recv_c);
    std::cout << "self-test ok\n";
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    try {
        if (argc < 2) {
            usage();
            return 2;
        }
        const std::string mode = argv[1];
        if (mode == "--help" || mode == "-h") {
            usage();
            return 0;
        }
        std::vector<std::string> positionals;
        config cfg = parse_args(argc, argv, positionals);
        std::optional<ephemeral_cert> generated;
        if (mode == "server") {
            if (cfg.cert.empty() && cfg.key.empty()) {
                generated = make_ephemeral_cert(cfg.bind_host);
                cfg.cert = generated->cert.string();
                cfg.key = generated->key.string();
            }
            return run_endpoint(std::move(cfg), true, positionals);
        }
        if (mode == "client")
            return run_endpoint(std::move(cfg), false, positionals);
        if (mode == "suite") {
            require_tls(cfg);
            if (!positionals.empty())
                throw std::runtime_error("suite takes no positional arguments");
            print_table(suite_cases(cfg));
            return 0;
        }
        if (mode == "self-test")
            return self_test(positionals);
        usage();
        return 2;
    } catch (const std::exception &err) {
        if (std::string(err.what()) == "help") {
            usage();
            return 0;
        }
        std::cerr << "spt_bench: " << err.what() << "\n";
        return 1;
    }
}
