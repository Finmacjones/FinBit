// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/peer_net.hpp"

#include "fb/crypto/identity_cert.hpp"
#include "fb/net/frame_codec.hpp"
#include "fb/net/tcp.hpp"
#include "fb/net/tls_client.hpp"
#include "fb/net/websocket.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

#if FB_HAVE_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <signal.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace fb::p2p {

namespace {

// Wait for socket readiness on POSIX or Windows. >0 = ready,
// 0 = timeout / interrupted, <0 = fatal.
int wait_socket_ready(int fd, bool want_read, bool want_write,
                      std::int64_t timeout_us) {
    if (timeout_us < 0) timeout_us = 0;
#if defined(_WIN32)
    WSAPOLLFD pfd{};
    pfd.fd     = static_cast<SOCKET>(static_cast<std::uintptr_t>(fd));
    pfd.events = 0;
    if (want_read)  pfd.events |= POLLRDNORM;
    if (want_write) pfd.events |= POLLWRNORM;
    pfd.revents = 0;
    int ms = static_cast<int>(timeout_us / 1000);
    int n = WSAPoll(&pfd, 1, ms);
    if (n == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAEINTR) return 0;
        return -1;
    }
    return n;
#else
    timeval tv{};
    tv.tv_sec  = timeout_us / 1'000'000;
    tv.tv_usec = timeout_us % 1'000'000;
    fd_set rd, wr;
    FD_ZERO(&rd); FD_ZERO(&wr);
    if (want_read)  FD_SET(fd, &rd);
    if (want_write) FD_SET(fd, &wr);
    const int sel = ::select(fd + 1,
                              want_read  ? &rd : nullptr,
                              want_write ? &wr : nullptr,
                              nullptr, &tv);
    if (sel < 0 && errno == EINTR) return 0;
    return sel;
#endif
}

// Per-process OpenSSL bootstrap (idempotent).
struct OpenSslInit {
    OpenSslInit() {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#if !defined(_WIN32)
        // SIGPIPE → EPIPE on write() to a torn-down socket. Without
        // this the entire process gets killed when a peer drops mid-
        // send (common on TLS-handshake-failure paths). Windows has
        // no SIGPIPE; closed sockets return WSAESHUTDOWN.
        ::signal(SIGPIPE, SIG_IGN);
#endif
    }
};
OpenSslInit& openssl_init() { static OpenSslInit i; return i; }

[[noreturn]] void throw_openssl(const std::string& ctx) {
    char buf[256] = {0};
    const auto err = ERR_get_error();
    if (err != 0) ERR_error_string_n(err, buf, sizeof(buf));
    else std::snprintf(buf, sizeof(buf), "(no OpenSSL error queued)");
    throw std::runtime_error("PeerNet " + ctx + ": " + buf);
}

// Parse "wss://host:port" → (host, port). Returns false on malformed
// input. PeerNet only speaks TLS, so any other scheme is rejected.
bool parse_wss_addr(const std::string& addr,
                     std::string& host, std::uint16_t& port) {
    constexpr std::string_view kPrefix = "wss://";
    if (addr.size() <= kPrefix.size() ||
        addr.compare(0, kPrefix.size(), kPrefix) != 0) return false;
    auto rest = addr.substr(kPrefix.size());
    // Strip any fragment (#hexfingerprint) before splitting host/port —
    // the fragment is metadata for the caller's pin check, not part
    // of the connect target. parse_pinned_addr exposes it separately.
    auto hash = rest.find('#');
    if (hash != std::string::npos) rest = rest.substr(0, hash);
    auto colon = rest.rfind(':');
    if (colon == std::string::npos) return false;
    host = rest.substr(0, colon);
    if (!host.empty() && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    auto port_str = rest.substr(colon + 1);
    int p = std::atoi(port_str.c_str());
    if (p <= 0 || p > 65535) return false;
    port = static_cast<std::uint16_t>(p);
    return true;
}

// Drive a single SSL_* call (read or write) until it succeeds or the
// deadline expires. SSL is non-blocking; we select() on the requested
// direction between attempts. Returns the SSL_* return value.
template <class Op>
int drive_ssl_io(SSL* ssl, int fd, Op&& op,
                  std::chrono::steady_clock::time_point deadline) {
    while (true) {
        int rc = op();
        if (rc > 0) return rc;
        const int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            return rc;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        const auto remaining = std::chrono::duration_cast<
            std::chrono::microseconds>(deadline - now).count();
        (void)wait_socket_ready(fd,
            err == SSL_ERROR_WANT_READ,
            err == SSL_ERROR_WANT_WRITE,
            static_cast<std::int64_t>(remaining));
    }
}

// Server-side TLS connection (counterpart to TlsClient — same
// blocking_read / blocking_send_all shape but with SSL_accept on
// the handshake instead of SSL_connect). Owns the fd + SSL*.
struct AcceptedConn {
    fb::net::Socket sock;
    SSL*            ssl = nullptr;

    AcceptedConn() = default;
    AcceptedConn(AcceptedConn&& o) noexcept
        : sock(std::move(o.sock)), ssl(o.ssl) { o.ssl = nullptr; }
    AcceptedConn& operator=(AcceptedConn&&) = delete;
    AcceptedConn(const AcceptedConn&)        = delete;
    AcceptedConn& operator=(const AcceptedConn&) = delete;

    ~AcceptedConn() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    // Drive SSL_accept to completion. Returns true on success.
    bool handshake() {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (true) {
            int rc = SSL_accept(ssl);
            if (rc == 1) return true;
            int err = SSL_get_error(ssl, rc);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                return false;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return false;
            const auto remaining = std::chrono::duration_cast<
                std::chrono::microseconds>(deadline - now).count();
            (void)wait_socket_ready(sock.fd(),
                err == SSL_ERROR_WANT_READ,
                err == SSL_ERROR_WANT_WRITE,
                static_cast<std::int64_t>(remaining));
        }
    }

    void blocking_send_all(std::span<const std::uint8_t> data) {
        if (data.empty()) return;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(30);
        std::size_t off = 0;
        while (off < data.size()) {
            int n = drive_ssl_io(ssl, sock.fd(), [&]() {
                return SSL_write(ssl, data.data() + off,
                                 static_cast<int>(data.size() - off));
            }, deadline);
            if (n <= 0) {
                throw std::runtime_error(
                    "AcceptedConn::send: SSL_write failed (rc=" +
                    std::to_string(n) + ")");
            }
            off += static_cast<std::size_t>(n);
        }
    }

    std::size_t blocking_read(std::span<std::uint8_t> out, int timeout_ms) {
        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(timeout_ms);
        int n = drive_ssl_io(ssl, sock.fd(), [&]() {
            return SSL_read(ssl, out.data(), static_cast<int>(out.size()));
        }, deadline);
        if (n <= 0) return 0;
        return static_cast<std::size_t>(n);
    }
};

// ---------------------------------------------------------------------------
// WebSocket framing role (Tier-2 mimicry). kNone = legacy raw
// length-prefixed frames. kDialer/kAcceptor select the masked/unmasked
// direction per RFC 6455 (client masks, server doesn't).
// ---------------------------------------------------------------------------
enum class WsRole { kNone, kDialer, kAcceptor };

// Dialer-side WS upgrade over an already-connected channel (TlsClient).
// Returns the bytes that arrived after the 101 response (the first WS
// frame may be piggy-backed). Throws on rejection / timeout.
template <class Channel>
std::vector<std::uint8_t> ws_client_upgrade(Channel& ch,
                                            const std::string& host,
                                            std::uint16_t port) {
    auto up = fb::net::ws::build_client_upgrade_request(host, port, "/");
    ch.blocking_send_all(std::span<const std::uint8_t>(
        up.request.data(), up.request.size()));
    fb::net::ws::ClientHandshakeParser hp(up.sec_key);
    std::array<std::uint8_t, 4096> buf{};
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        const auto n = ch.blocking_read(
            std::span<std::uint8_t>(buf.data(), buf.size()),
            static_cast<int>(remaining));
        if (n == 0) continue;
        const auto st = hp.feed(std::span<const std::uint8_t>(buf.data(), n));
        if (st == fb::net::ws::ClientHandshakeParser::Status::kAccepted) {
            auto t = hp.trailing();
            return std::vector<std::uint8_t>(t.begin(), t.end());
        }
        if (st == fb::net::ws::ClientHandshakeParser::Status::kRejected) {
            throw std::runtime_error("ws_client_upgrade rejected: " + hp.reason());
        }
    }
    throw std::runtime_error("ws_client_upgrade timed out");
}

// Acceptor-side auto-detection. Reads the first chunk: if it's an HTTP
// upgrade ("GET "), completes the RFC 6455 server handshake (sends 101)
// and reports role=kAcceptor with any trailing bytes; otherwise reports
// role=kNone and hands back the bytes it read so the caller seeds them
// into the raw FrameDecoder. Returns kNone with no prebuffer on a
// dead/empty connection.
struct WsDetect {
    WsRole                    role = WsRole::kNone;
    std::vector<std::uint8_t> prebuffer;
};
template <class Channel>
WsDetect ws_detect_and_accept(Channel& ch) {
    WsDetect out;
    std::array<std::uint8_t, 4096> buf{};
    const auto first_n = ch.blocking_read(
        std::span<std::uint8_t>(buf.data(), buf.size()), 5000);
    if (first_n == 0) return out;  // nothing arrived / closed
    std::vector<std::uint8_t> first(buf.data(), buf.data() + first_n);

    const bool looks_http = first_n >= 4 && first[0] == 'G' &&
        first[1] == 'E' && first[2] == 'T' && first[3] == ' ';
    if (!looks_http) {
        out.prebuffer = std::move(first);  // raw frame bytes
        return out;
    }

    fb::net::ws::HandshakeParser hp;
    auto st = hp.feed(std::span<const std::uint8_t>(first.data(), first.size()));
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (st == fb::net::ws::HandshakeParser::Status::kNeedMore &&
           std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        const auto m = ch.blocking_read(
            std::span<std::uint8_t>(buf.data(), buf.size()),
            static_cast<int>(remaining));
        if (m == 0) break;
        st = hp.feed(std::span<const std::uint8_t>(buf.data(), m));
    }
    if (st != fb::net::ws::HandshakeParser::Status::kAccepted) {
        throw std::runtime_error("ws_detect_and_accept: handshake failed");
    }
    const auto accept = fb::net::ws::compute_accept(hp.client_key());
    const auto resp = fb::net::ws::build_101_response(accept);
    ch.blocking_send_all(std::span<const std::uint8_t>(resp.data(), resp.size()));
    out.role = WsRole::kAcceptor;
    auto t = hp.trailing();
    out.prebuffer.assign(t.begin(), t.end());
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Per-connection state. Used for both inbound (AcceptedConn) and
// outbound (TlsClient) — they share the read-loop / write-queue logic.
// ---------------------------------------------------------------------------

struct PeerNet::Impl {
    // Listener state.
    SSL_CTX*                            server_ctx = nullptr;
    std::optional<fb::net::Socket>      listen_sock;
    std::uint16_t                       listen_port = 0;
    std::atomic_bool                    listen_running{false};
    std::optional<std::thread>          accept_thread;

    // Dialer config.
    PeerDialerOptions                    dialer_opts;
    std::atomic_bool                    dialer_set{false};

    // Inbound dispatch callback.
    std::mutex                          cb_mu;
    OnMessage                           on_msg;

    // Generic per-connection worker — owns the SSL channel (either an
    // AcceptedConn or a TlsClient), a write queue, and the read loop.
    struct Worker {
        std::atomic_bool         stop{false};
        std::mutex               mu;
        std::condition_variable  cv;
        std::deque<std::vector<std::uint8_t>> writes;
        std::thread              thread;

        void enqueue(std::vector<std::uint8_t> bytes) {
            {
                std::lock_guard lk(mu);
                writes.push_back(std::move(bytes));
            }
            cv.notify_all();
        }
        std::optional<std::vector<std::uint8_t>> dequeue_for(int ms) {
            std::unique_lock lk(mu);
            cv.wait_for(lk, std::chrono::milliseconds(ms),
                         [&] { return stop || !writes.empty(); });
            if (writes.empty()) return std::nullopt;
            auto out = std::move(writes.front());
            writes.pop_front();
            return out;
        }
    };

    // Outbound: keyed by addr ("wss://host:port"). Pool size is one
    // connection per peer addr.
    std::mutex                                  out_mu;
    std::map<std::string, std::shared_ptr<Worker>> out_conns;

    // Inbound: just a list, kept alive for as long as the connection
    // stays open.
    std::mutex                                  in_mu;
    std::vector<std::shared_ptr<Worker>>        in_conns;

    std::atomic_bool global_stop{false};

    ~Impl() {
        // Tear down listener first so no new inbound spin up.
        listen_running = false;
        if (accept_thread && accept_thread->joinable()) {
            // Force-shutdown the fd so a select() inside the accept
            // thread wakes immediately. We DON'T close it yet — the
            // accept thread might still be in tcp_accept(); it'll
            // see EBADF, the catch block exits the loop, and only
            // THEN do we drop the Socket which closes the fd for
            // real.
            if (listen_sock) {
#if defined(_WIN32)
                ::shutdown(static_cast<SOCKET>(static_cast<std::uintptr_t>(
                               listen_sock->fd())),
                            SD_BOTH);
#else
                ::shutdown(listen_sock->fd(), SHUT_RDWR);
#endif
            }
            accept_thread->join();
            listen_sock.reset();
        }
        global_stop = true;
        // Stop all workers.
        {
            std::vector<std::shared_ptr<Worker>> snap_out;
            {
                std::lock_guard lk(out_mu);
                for (auto& [_, w] : out_conns) snap_out.push_back(w);
                out_conns.clear();
            }
            for (auto& w : snap_out) {
                w->stop = true;
                w->cv.notify_all();
            }
            for (auto& w : snap_out) {
                if (w->thread.joinable()) w->thread.join();
            }
        }
        {
            std::vector<std::shared_ptr<Worker>> snap_in;
            {
                std::lock_guard lk(in_mu);
                snap_in.swap(in_conns);
            }
            for (auto& w : snap_in) {
                w->stop = true;
                w->cv.notify_all();
            }
            for (auto& w : snap_in) {
                if (w->thread.joinable()) w->thread.join();
            }
        }
        if (server_ctx) SSL_CTX_free(server_ctx);
    }

    // The shared read/write loop. Templated over the channel type so
    // both AcceptedConn (server-side) and TlsClient (client-side)
    // work without duplicating the body.
    //
    // `ws_role` selects the framing: kNone = length-prefixed raw frames
    // (legacy); kDialer/kAcceptor = RFC 6455 WS framing (Tier-2
    // mimicry) with the correct mask direction for each end. Any
    // `prebuffered` bytes (e.g. trailing bytes after a WS upgrade, or
    // the first chunk a raw acceptor already read during detection) are
    // fed into the de-framer before the main loop starts.
    template <class Channel>
    void run_loop(Channel& ch, Worker& w, const PeerInfo& peer_label,
                  WsRole ws_role = WsRole::kNone,
                  const std::vector<std::uint8_t>& prebuffered = {}) {
        const bool ws = (ws_role != WsRole::kNone);
        fb::net::FrameDecoder dec;
        fb::net::ws::FrameParser wsp(
            /*expect_masked=*/ws_role == WsRole::kAcceptor);
        std::array<std::uint8_t, 4096> rbuf{};

        auto frame_out = [&](std::span<const std::uint8_t> p) {
            if (ws_role == WsRole::kDialer)
                return fb::net::ws::build_client_binary_frame(p);
            if (ws_role == WsRole::kAcceptor)
                return fb::net::ws::build_server_binary_frame(p);
            return fb::net::encode_frame(p);
        };
        auto feed = [&](std::span<const std::uint8_t> b) {
            if (ws) wsp.feed(b); else dec.feed(b);
        };
        auto deliver_ready = [&]() {
            std::vector<std::uint8_t> frame;
            for (;;) {
                bool ready;
                if (ws) {
                    ready = wsp.try_pop(frame) ==
                            fb::net::ws::FrameParser::PopStatus::kFrameReady;
                } else {
                    ready = dec.try_pop(frame) ==
                            fb::net::FrameDecoder::Status::kFrameReady;
                }
                if (!ready) break;
                OnMessage cb_copy;
                {
                    std::lock_guard lk(cb_mu);
                    cb_copy = on_msg;
                }
                if (cb_copy) {
                    cb_copy(peer_label,
                             std::span<const std::uint8_t>(
                                 frame.data(), frame.size()));
                }
            }
        };

        try {
            if (!prebuffered.empty()) {
                feed(std::span<const std::uint8_t>(
                    prebuffered.data(), prebuffered.size()));
                deliver_ready();
            }
            while (!w.stop && !global_stop) {
                // 1. Drain queued writes (non-blocking, take what's
                //    there in a single dequeue cycle).
                while (auto pending = w.dequeue_for(/*ms=*/0)) {
                    auto framed = frame_out(
                        std::span<const std::uint8_t>(
                            pending->data(), pending->size()));
                    ch.blocking_send_all(
                        std::span<const std::uint8_t>(
                            framed.data(), framed.size()));
                }
                // 2. Read with a short timeout — also serves as our
                //    "poll for new writes" wait.
                auto n = ch.blocking_read(
                    std::span<std::uint8_t>(rbuf.data(), rbuf.size()),
                    /*timeout_ms=*/100);
                if (n > 0) {
                    feed(std::span<const std::uint8_t>(rbuf.data(), n));
                    deliver_ready();
                }
                // 3. If there are still queued writes, loop back and
                //    drain them. Otherwise wait briefly for new
                //    queue activity (the dequeue_for(0) in step 1
                //    is non-blocking; combine with read-poll above).
            }
        } catch (...) {
            // Connection died (peer hung up, TLS error). Drop out
            // of the loop; the destructor will join us.
        }
    }
};

PinnedAddr parse_pinned_addr(const std::string& addr) {
    PinnedAddr out;
    auto hash = addr.find('#');
    if (hash == std::string::npos) {
        out.addr_without_fragment = addr;
        return out;
    }
    out.addr_without_fragment = addr.substr(0, hash);
    out.pin_fragment_hex      = addr.substr(hash + 1);
    return out;
}

PeerNet::PeerNet() : impl_(std::make_unique<Impl>()) { openssl_init(); }
PeerNet::~PeerNet() = default;

void PeerNet::start_listener(const PeerListenerOptions& opts) {
    if (impl_->listen_sock) {
        throw std::runtime_error("PeerNet: listener already started");
    }
    if (opts.tls_cert_pem.empty() || opts.tls_key_pem.empty()) {
        throw std::runtime_error(
            "PeerNet::start_listener: tls_cert_pem and tls_key_pem are required");
    }
    impl_->server_ctx = SSL_CTX_new(TLS_server_method());
    if (!impl_->server_ctx) throw_openssl("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(impl_->server_ctx, TLS1_2_VERSION);
    // Mutual auth: when require_client_cert is true, we ask for a
    // client cert AND fail the handshake if none is presented.
    // Otherwise we still REQUEST one (so peers that have one will
    // present it, letting us extract their pubkey) but don't reject
    // anonymous dialers. The chain-check would always fail (peer
    // certs are self-signed at the identity key, no useful CA
    // exists) so the verify_callback always returns 1 — actual
    // pubkey binding happens at the application layer after the
    // handshake.
    int verify_mode = SSL_VERIFY_PEER;
    if (opts.require_client_cert) {
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(impl_->server_ctx, verify_mode,
        [](int /*preverify_ok*/, X509_STORE_CTX*) -> int { return 1; });
    if (SSL_CTX_use_certificate_chain_file(
            impl_->server_ctx, opts.tls_cert_pem.c_str()) != 1) {
        throw_openssl("use_certificate_chain_file");
    }
    if (SSL_CTX_use_PrivateKey_file(impl_->server_ctx,
                                      opts.tls_key_pem.c_str(),
                                      SSL_FILETYPE_PEM) != 1) {
        throw_openssl("use_PrivateKey_file");
    }
    if (SSL_CTX_check_private_key(impl_->server_ctx) != 1) {
        throw_openssl("check_private_key");
    }

    // Bind the listening socket. Queries the kernel-assigned port
    // when bind_port=0 so tests can grab a free port without races.
    impl_->listen_sock.emplace(
        fb::net::tcp_listen(opts.bind_host, opts.bind_port));
    sockaddr_in sa{};
#if defined(_WIN32)
    int sl = sizeof(sa);
    if (::getsockname(static_cast<SOCKET>(static_cast<std::uintptr_t>(
                          impl_->listen_sock->fd())),
                       reinterpret_cast<sockaddr*>(&sa), &sl) == 0) {
#else
    socklen_t sl = sizeof(sa);
    if (::getsockname(impl_->listen_sock->fd(),
                       reinterpret_cast<sockaddr*>(&sa), &sl) == 0) {
#endif
        impl_->listen_port = ntohs(sa.sin_port);
    } else {
        impl_->listen_port = opts.bind_port;
    }

    impl_->listen_running = true;
    // Capture the fd by value so the accept thread doesn't race with
    // the destructor's listen_sock.reset(). The destructor closes
    // the fd via shutdown() to wake select(); accept4() then returns
    // EBADF, which we catch + break out of cleanly.
    const int lfd = impl_->listen_sock->fd();
    impl_->accept_thread.emplace([this, lfd]() {
        while (impl_->listen_running) {
            const int sel = wait_socket_ready(lfd,
                /*want_read=*/true, /*want_write=*/false,
                /*timeout_us=*/100 * 1000);
            if (sel < 0) break;        // fd closed during shutdown
            if (sel == 0) continue;    // timeout
            fb::net::Socket s;
            try {
                s = fb::net::tcp_accept(lfd);
            } catch (...) {
                // Fd was closed by the destructor between select()
                // and accept4(). Exit the loop cleanly.
                break;
            }
            if (!s.valid()) continue;
            // Wrap with SSL.
            auto conn = std::make_unique<AcceptedConn>();
            conn->sock = std::move(s);
            conn->ssl = SSL_new(impl_->server_ctx);
            if (!conn->ssl) continue;
            SSL_set_fd(conn->ssl, conn->sock.fd());
            SSL_set_accept_state(conn->ssl);
            if (!conn->handshake()) {
                continue;   // bad client / cert / etc.
            }
            // Mutual-TLS: extract the client's Ed25519 pubkey from
            // their cert so on_message receives a PeerInfo with the
            // identity TLS-attested. Without this the application
            // layer would be back to trusting a self-stamped
            // sender_pubkey field.
            PeerInfo from{};
            X509* peer_cert = SSL_get_peer_certificate(conn->ssl);
            if (peer_cert) {
                EVP_PKEY* pkey = X509_get_pubkey(peer_cert);
                if (pkey && EVP_PKEY_id(pkey) == EVP_PKEY_ED25519) {
                    std::array<std::uint8_t, 32> pub{};
                    std::size_t len = pub.size();
                    if (EVP_PKEY_get_raw_public_key(
                            pkey, pub.data(), &len) == 1 && len == 32) {
                        from.pubkey.assign(pub.begin(), pub.end());
                        from.id = node_id_from_pubkey(
                            std::span<const std::uint8_t>(
                                pub.data(), pub.size()));
                    }
                }
                if (pkey) EVP_PKEY_free(pkey);
                X509_free(peer_cert);
            }
            // Spawn a worker thread to drive the connection.
            auto w = std::make_shared<Impl::Worker>();
            // Move conn into the lambda capture.
            auto conn_ptr = std::shared_ptr<AcceptedConn>(conn.release());
            w->thread = std::thread(
                [this, w_weak = std::weak_ptr<Impl::Worker>(w),
                 conn_ptr, from]() mutable {
                    auto strong = w_weak.lock();
                    if (!strong) return;
                    // Auto-detect WS vs raw on the first inbound bytes so
                    // a WSS dialer and a raw dialer both interoperate
                    // with this listener (Tier-2 mimicry).
                    WsRole role = WsRole::kNone;
                    std::vector<std::uint8_t> pre;
                    try {
                        auto det = ws_detect_and_accept(*conn_ptr);
                        role = det.role;
                        pre  = std::move(det.prebuffer);
                    } catch (...) {
                        strong->stop = true;
                        return;
                    }
                    impl_->run_loop(*conn_ptr, *strong, from, role, pre);
                });
            {
                std::lock_guard lk(impl_->in_mu);
                impl_->in_conns.push_back(std::move(w));
            }
        }
    });
}

std::uint16_t PeerNet::listener_port() const noexcept {
    return impl_->listen_port;
}

void PeerNet::set_dialer(const PeerDialerOptions& opts) {
    impl_->dialer_opts = opts;
    impl_->dialer_set = true;
}

void PeerNet::set_on_message(OnMessage cb) {
    std::lock_guard lk(impl_->cb_mu);
    impl_->on_msg = std::move(cb);
}

bool PeerNet::send(const PeerInfo& peer,
                    std::span<const std::uint8_t> bytes) {
    std::string host;
    std::uint16_t port = 0;
    if (!parse_wss_addr(peer.addr, host, port)) return false;

    // Look up or create the outbound worker for this addr.
    std::shared_ptr<Impl::Worker> w;
    {
        std::lock_guard lk(impl_->out_mu);
        auto it = impl_->out_conns.find(peer.addr);
        if (it != impl_->out_conns.end()) {
            w = it->second;
        } else {
            w = std::make_shared<Impl::Worker>();
            impl_->out_conns[peer.addr] = w;
            // Spawn the outbound worker. The dial happens INSIDE
            // the worker thread so a slow handshake doesn't block
            // send().
            const auto dialer_opts = impl_->dialer_opts;
            const PeerInfo peer_copy = peer;
            w->thread = std::thread(
                [this, w_weak = std::weak_ptr<Impl::Worker>(w),
                 host, port, dialer_opts, peer_copy]() {
                    auto strong = w_weak.lock();
                    if (!strong) return;
                    fb::net::TlsClient tls;
                    fb::net::TlsClientOptions topts;
                    topts.ca_file              = dialer_opts.ca_file;
                    topts.insecure_skip_verify = dialer_opts.insecure_skip_verify;
                    topts.sni_hostname         = host;
                    topts.client_cert_pem      = dialer_opts.client_cert_pem;
                    topts.client_key_pem       = dialer_opts.client_key_pem;
                    if (peer_copy.pubkey.size() == 32) {
                        std::copy_n(peer_copy.pubkey.begin(), 32,
                                     topts.expected_peer_pubkey.begin());
                        topts.expected_peer_pubkey_set = true;
                    }
                    WsRole role = WsRole::kNone;
                    std::vector<std::uint8_t> pre;
                    try {
                        tls.connect(host, port, topts);
                        if (dialer_opts.wss) {
                            // Tier-2: cloak the P2P link as browser WSS.
                            pre  = ws_client_upgrade(tls, host, port);
                            role = WsRole::kDialer;
                        }
                    } catch (const std::exception&) {
                        // Dial (or WS upgrade) failed — bail. The pool
                        // entry stays (with stop=true) so re-tries don't
                        // busy-dial; ChatClient's higher layer is
                        // expected to clear stale entries.
                        strong->stop = true;
                        return;
                    }
                    impl_->run_loop(tls, *strong, peer_copy, role, pre);
                });
        }
    }
    // Enqueue the bytes (regardless of whether the dial finished —
    // the worker drains the queue once connected).
    w->enqueue(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
    return true;
}

void PeerNet::shutdown() { impl_.reset(); }

std::size_t PeerNet::outbound_count() const {
    std::lock_guard lk(impl_->out_mu);
    return impl_->out_conns.size();
}
std::size_t PeerNet::inbound_count() const {
    std::lock_guard lk(impl_->in_mu);
    return impl_->in_conns.size();
}

}  // namespace fb::p2p

#else   // FB_HAVE_OPENSSL == 0

namespace fb::p2p {

struct PeerNet::Impl {};

PeerNet::PeerNet()  : impl_(std::make_unique<Impl>()) {}
PeerNet::~PeerNet() = default;

[[noreturn]] static void unimpl() {
    throw std::runtime_error(
        "PeerNet: OpenSSL not compiled in. Rebuild with OpenSSL "
        "available so FB_HAVE_OPENSSL=1.");
}

void PeerNet::start_listener(const PeerListenerOptions&)  { unimpl(); }
std::uint16_t PeerNet::listener_port() const noexcept     { return 0; }
void PeerNet::set_dialer(const PeerDialerOptions&)        { unimpl(); }
void PeerNet::set_on_message(OnMessage)                   { unimpl(); }
bool PeerNet::send(const PeerInfo&,
                    std::span<const std::uint8_t>)        { unimpl(); }
void PeerNet::shutdown()                                  {}
std::size_t PeerNet::outbound_count() const               { return 0; }
std::size_t PeerNet::inbound_count()  const               { return 0; }

}  // namespace fb::p2p

#endif  // FB_HAVE_OPENSSL
