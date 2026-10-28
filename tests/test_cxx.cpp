#include "parsock.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <signal.h>
#include <unistd.h>

static int fails;

static void expect(bool cond, const char *msg)
{
    if (!cond) {
        std::cerr << "fail: " << msg << "\n";
        fails++;
    }
}

static void on_alarm(int)
{
    std::cerr << "fail: cxx timed out\n";
    _exit(2);
}

static std::uint8_t pattern(std::size_t off)
{
    return static_cast<std::uint8_t>((off * 131u) ^ (off >> 8));
}

static parsock::options make_options(const std::string &cert, const std::string &key)
{
    return parsock::options()
        .certificate(cert)
        .private_key(key)
        .ca_file(cert)
        .server_name("127.0.0.1")
        .verify_peer(true)
        .sockets(2)
        .frame_size(16384)
        .receive_window(65536)
        .connect_timeout(10000)
        .io_timeout(15000);
}

static void check_options_lifetime()
{
    parsock::options original = parsock::options().certificate("cert.pem").private_key("key.pem");
    parsock::options copied = original;
    original.certificate("other.pem");
    expect(std::strcmp(copied.native().tls->cert_file, "cert.pem") == 0, "copy keeps certificate");
    expect(std::strcmp(original.native().tls->cert_file, "other.pem") == 0, "original retargets");
    parsock::options moved = std::move(copied);
    expect(std::strcmp(moved.native().tls->cert_file, "cert.pem") == 0, "move keeps certificate");
    expect(moved.native().min_protection == PS_PROTECTION_CONFIDENTIAL, "default floor");
}

static void echo_case(const parsock::options &opt, parsock::protection profile, std::size_t nbytes)
{
    parsock::listener ln = parsock::listener::listen("127.0.0.1", 0, opt);
    const parsock::endpoints ports = ln.ports();
    expect(ports.control != 0 && ports.data != 0, "ports");
    std::atomic<int> server_rc{0};
    std::thread server([&] {
        try {
            parsock::connection conn = ln.accept();
            std::vector<std::uint8_t> buf(8192);
            for (;;) {
                const std::size_t n = conn.recv(buf.data(), buf.size());
                if (n == 0)
                    break;
                conn.send(buf.data(), n, profile);
            }
        } catch (const parsock::failure &err) {
            std::cerr << "server: " << err.what() << "\n";
            server_rc = 1;
        }
    });

    try {
        parsock::connection conn = parsock::connection::connect("127.0.0.1", ports.control, opt);
        expect(conn.state() == parsock::session_state::open, "open");
        std::vector<std::uint8_t> tx(nbytes);
        for (std::size_t i = 0; i < tx.size(); i++)
            tx[i] = pattern(i);
        conn.send(tx, profile);
        const parsock::stats st = conn.statistics();
        expect(st.app_bytes_sent == nbytes, "stats");
        expect(st.active_sockets == 2, "sockets");
        (void)conn.advice();
        conn.shutdown_write();
        std::vector<std::uint8_t> rx(nbytes);
        std::size_t got = 0;
        while (got < rx.size()) {
            const std::size_t n = conn.recv(rx.data() + got, rx.size() - got);
            if (n == 0)
                throw parsock::failure(parsock::errc::closed);
            got += n;
        }
        expect(rx == tx, "echo bytes");
        parsock::connection moved = std::move(conn);
        expect(!conn, "moved from");
        expect(static_cast<bool>(moved), "moved to");
    } catch (const parsock::failure &err) {
        std::cerr << "client: " << err.what() << "\n";
        fails++;
    }
    server.join();
    if (server_rc != 0)
        fails++;
}

static void reject_case(const std::string &cert, const std::string &key)
{
    parsock::options server_opt = make_options(cert, key);
    parsock::options client_opt = server_opt;
    client_opt.minimum_protection(parsock::protection::authenticated);
    parsock::listener ln = parsock::listener::listen("127.0.0.1", 0, server_opt);
    const auto ports = ln.ports();
    std::thread server([&] {
        try {
            parsock::connection conn = ln.accept();
            std::vector<std::uint8_t> buf(256);
            const std::size_t n = conn.recv(buf.data(), buf.size());
            if (n > 0)
                conn.send(buf.data(), n);
        } catch (const parsock::failure &err) {
            std::cerr << "reject server: " << err.what() << "\n";
            fails++;
        }
    });
    parsock::connection conn = parsock::connection::connect("127.0.0.1", ports.control, client_opt);
    bool threw = false;
    try {
        conn.send(std::string_view{"public-looking"}, parsock::protection::authenticated);
    } catch (const parsock::failure &err) {
        threw = true;
        expect(err.code() == parsock::errc::authentication, "auth code");
    }
    expect(threw, "authenticated send rejected");
    conn.send(std::string_view{"still-secret"});
    conn.shutdown_write();
    server.join();
}

static void session_case(const parsock::options &opt)
{
    int pokes = 0;
    parsock::io_handlers handlers;
    handlers.poke = [&] { pokes++; };
    handlers.on_error = [](parsock::errc) { throw std::runtime_error("session error"); };
    parsock::session session = parsock::session::create(true, opt, std::move(handlers));
    session.set_data_port(9);
    expect(session.state() == parsock::session_state::init, "session init");
    bool waiting_for_hello = false;
    try {
        (void)session.session_id();
    } catch (const parsock::failure &err) {
        waiting_for_hello = err.code() == parsock::errc::again;
    }
    expect(waiting_for_hello, "session id waits for hello");
    const parsock::transfer blocked = session.try_send(std::string_view{"x"}.data(), 1);
    expect(blocked.blocked && blocked.count == 0, "send before open blocks");
    (void)session.watches();
    (void)session.statistics();
    session.service();
    expect(pokes >= 0, "poke callback installed");

    int pids[2] = {-1, -1};
    expect(pipe(pids) == 0, "pipe");

    parsock::device_mem dmem{};
    dmem.type = PS_MEM_HOST;
    dmem.ptr = pids;
    dmem.length = sizeof(pids);
    dmem.dmabuf_fd = -1;
    expect(dmem.type == static_cast<ps_mem_type_t>(parsock::mem_type::host), "dmem type");
    close(pids[1]);
    bool preface_failed = false;
    try {
        (void)parsock::read_preface(pids[0], 50);
    } catch (const parsock::failure &) {
        preface_failed = true;
    }
    close(pids[0]);
    expect(preface_failed, "short preface");
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "usage: test_cxx cert key\n";
        return 2;
    }
    signal(SIGALRM, on_alarm);
    alarm(45);
    check_options_lifetime();
    const parsock::options opt = make_options(argv[1], argv[2]);
    echo_case(opt, parsock::protection::confidential, 32 * 1024);
    parsock::options auth = opt;
    auth.minimum_protection(parsock::protection::authenticated);
    echo_case(auth, parsock::protection::authenticated, 24 * 1024);
    reject_case(argv[1], argv[2]);
    session_case(opt);
    bool refused = false;
    try {
        parsock::options fast = opt;
        fast.connect_timeout(200);
        (void)parsock::connection::connect("127.0.0.1", 1, fast);
    } catch (const parsock::failure &) {
        refused = true;
    }
    expect(refused, "refused connect");
    alarm(0);
    if (fails) {
        std::cerr << fails << " cxx checks failed\n";
        return 1;
    }
    return 0;
}
