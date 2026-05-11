// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/peer_net.hpp"

#if defined(_WIN32)
#  error "peer_net.cpp uses POSIX sockets + select() (arpa/inet, netinet/in, \
sys/socket, sys/select). Windows port required: Winsock2 + WSAPoll. \
Depends on tcp.cpp and tls_client.cpp being ported first. \
Tracked in docs/windows-port-status.md."
#endif

#include "fb/crypto/identity_cert.hpp"
#include "fb/net/frame_codec.hpp"
#include "fb/net/tcp.hpp"
#include "fb/net/tls_client.hpp"

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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fb::p2p {

namespace {

// Per-process OpenSSL bootstrap (idempotent).
struct OpenSslInit {
    OpenSslInit() {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        // SIGPIPE → EPIPE on write() to a torn-down socket. Without
        // this the entire process gets killed when a peer drops mid-
        // send (common on TLS-handshake-failure paths).
        ::signal(SIGPIPE, SIG_IGN);
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
        timeval tv{};
        tv.tv_sec  = remaining / 1'000'000;
        tv.tv_usec = remaining % 1'000'000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        if (err == SSL_ERROR_WANT_READ) {
            ::select(fd + 1, &fds, nullptr, nullptr, &tv);
        } else {
            ::select(fd + 1, nullptr, &fds, nullptr, &tv);
        }
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
            timeval tv{};
            tv.tv_sec  = remaining / 1'000'000;
            tv.tv_usec = remaining % 1'000'000;
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock.fd(), &fds);
            if (err == SSL_ERROR_WANT_READ) {
                ::select(sock.fd() + 1, &fds, nullptr, nullptr, &tv);
            } else {
                ::select(sock.fd() + 1, nullptr, &fds, nullptr, &tv);
            }
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
                ::shutdown(listen_sock->fd(), SHUT_RDWR);
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
    template <class Channel>
    void run_loop(Channel& ch, Worker& w, const PeerInfo& peer_label) {
        fb::net::FrameDecoder dec;
        std::array<std::uint8_t, 4096> rbuf{};
        try {
            while (!w.stop && !global_stop) {
                // 1. Drain queued writes (non-blocking, take what's
                //    there in a single dequeue cycle).
                while (auto pending = w.dequeue_for(/*ms=*/0)) {
                    auto framed = fb::net::encode_frame(
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
                    dec.feed(std::span<const std::uint8_t>(
                        rbuf.data(), n));
                    std::vector<std::uint8_t> frame;
                    while (dec.try_pop(frame) ==
                           fb::net::FrameDecoder::Status::kFrameReady) {
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
    socklen_t   sl = sizeof(sa);
    if (::getsockname(impl_->listen_sock->fd(),
                       reinterpret_cast<sockaddr*>(&sa), &sl) == 0) {
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
            timeval tv{};
            tv.tv_sec  = 0;
            tv.tv_usec = 100 * 1000;
            fd_set rs;
            FD_ZERO(&rs);
            FD_SET(lfd, &rs);
            const int sel = ::select(lfd + 1, &rs, nullptr, nullptr, &tv);
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
                    impl_->run_loop(*conn_ptr, *strong, from);
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
                    try {
                        tls.connect(host, port, topts);
                    } catch (const std::exception&) {
                        // Dial failed — bail. The pool entry stays
                        // (with stop=true) so re-tries don't busy-
                        // dial; ChatClient's higher layer is
                        // expected to clear stale entries.
                        strong->stop = true;
                        return;
                    }
                    impl_->run_loop(tls, *strong, peer_copy);
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
