// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/tls_client.hpp"

#include "fb/net/tcp.hpp"

#include <chrono>
#include <stdexcept>

#if FB_HAVE_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sys/select.h>
#include <unistd.h>

namespace fb::net {
namespace {

// Per-process OpenSSL init. SSL_library_init / SSL_load_error_strings
// became no-ops in OpenSSL 1.1+, but OPENSSL_init_ssl is the proper
// idempotent entry point.
struct InitOpenSSL {
    InitOpenSSL() {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    }
};
InitOpenSSL& openssl_init() {
    static InitOpenSSL init;
    return init;
}

[[noreturn]] void throw_openssl(const std::string& ctx) {
    char buf[256] = {0};
    const auto err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
    } else {
        std::snprintf(buf, sizeof(buf), "(no OpenSSL error queued)");
    }
    throw std::runtime_error("TlsClient " + ctx + ": " + buf);
}

}  // namespace

struct TlsClient::Impl {
    Socket socket;        // underlying TCP socket; owns the fd
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    bool connected = false;

    ~Impl() {
        if (ssl) {
            // Best-effort clean shutdown; ignore errors (peer may have
            // gone already).
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ctx) SSL_CTX_free(ctx);
    }
};

TlsClient::TlsClient() : impl_(std::make_unique<Impl>()) {
    openssl_init();
}
TlsClient::~TlsClient() = default;
TlsClient::TlsClient(TlsClient&&) noexcept = default;
TlsClient& TlsClient::operator=(TlsClient&&) noexcept = default;

void TlsClient::connect(const std::string& host, std::uint16_t port,
                          const TlsClientOptions& opts) {
    // 1. TLS context. SSLv23_client_method auto-negotiates the highest
    // mutually-supported TLS version (1.2 or 1.3 in practice).
    impl_->ctx = SSL_CTX_new(TLS_client_method());
    if (!impl_->ctx) throw_openssl("SSL_CTX_new");

    // Pin the floor at TLS 1.2 — anything older is broken.
    SSL_CTX_set_min_proto_version(impl_->ctx, TLS1_2_VERSION);

    if (opts.insecure_skip_verify) {
        SSL_CTX_set_verify(impl_->ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(impl_->ctx, SSL_VERIFY_PEER, nullptr);
        if (!opts.ca_file.empty()) {
            if (SSL_CTX_load_verify_locations(impl_->ctx,
                    opts.ca_file.c_str(), nullptr) != 1) {
                throw_openssl("load_verify_locations(" +
                              opts.ca_file + ")");
            }
        } else {
            // Fall back to the platform's CA bundle.
            if (SSL_CTX_set_default_verify_paths(impl_->ctx) != 1) {
                throw_openssl("set_default_verify_paths");
            }
        }
    }

    // 2. TCP connect.
    impl_->socket = tcp_connect(host, port);

    // 3. SSL object. Bind it to the socket fd.
    impl_->ssl = SSL_new(impl_->ctx);
    if (!impl_->ssl) throw_openssl("SSL_new");
    if (SSL_set_fd(impl_->ssl, impl_->socket.fd()) != 1) {
        throw_openssl("SSL_set_fd");
    }

    // 4. SNI + hostname verification. SNI is mandatory for any modern
    // server (vhosting, certificate selection); X509 hostname check
    // protects against MITM with a different valid cert.
    const std::string sni = opts.sni_hostname.empty() ? host : opts.sni_hostname;
    if (SSL_set_tlsext_host_name(impl_->ssl, sni.c_str()) != 1) {
        throw_openssl("SSL_set_tlsext_host_name");
    }
    if (!opts.insecure_skip_verify) {
        SSL_set_hostflags(impl_->ssl,
                          X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(impl_->ssl, sni.c_str()) != 1) {
            throw_openssl("SSL_set1_host(" + sni + ")");
        }
    }

    // 5. Handshake. tcp_connect returns a non-blocking socket, so
    // SSL_connect will routinely return WANT_READ / WANT_WRITE during
    // the handshake — we loop with select until the handshake either
    // completes or hits a real error. 10-second cap defends against a
    // misbehaving peer that never finishes ServerHello.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (true) {
        const int rc = SSL_connect(impl_->ssl);
        if (rc == 1) break;
        const int err = SSL_get_error(impl_->ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            // Drain the OpenSSL error queue for a useful diagnostic.
            char buf[256] = {0};
            const auto e = ERR_peek_last_error();
            if (e != 0) {
                ERR_error_string_n(e, buf, sizeof(buf));
            } else {
                std::snprintf(buf, sizeof(buf),
                              "(no OpenSSL error queued)");
            }
            const long verify = SSL_get_verify_result(impl_->ssl);
            throw std::runtime_error(
                "TlsClient handshake failed (SSL_get_error=" +
                std::to_string(err) + ", verify=" +
                std::to_string(verify) + ", openssl=" + buf + ")");
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error(
                "TlsClient handshake timed out after 10s");
        }
        const auto remaining = std::chrono::duration_cast<
            std::chrono::microseconds>(deadline - now).count();
        timeval tv{};
        tv.tv_sec  = remaining / 1'000'000;
        tv.tv_usec = remaining % 1'000'000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(impl_->socket.fd(), &fds);
        const int sel = (err == SSL_ERROR_WANT_READ)
            ? ::select(impl_->socket.fd() + 1, &fds, nullptr, nullptr, &tv)
            : ::select(impl_->socket.fd() + 1, nullptr, &fds, nullptr, &tv);
        if (sel < 0 && errno != EINTR) {
            throw std::runtime_error(
                "TlsClient handshake select failed");
        }
        // sel == 0 (timed out) → loop will re-check deadline and bail.
    }

    impl_->connected = true;
}

void TlsClient::blocking_send_all(std::span<const std::uint8_t> data) {
    if (!impl_->connected) {
        throw std::runtime_error("TlsClient::send: not connected");
    }
    if (data.empty()) return;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(30);
    std::size_t off = 0;
    while (off < data.size()) {
        const int n = SSL_write(impl_->ssl, data.data() + off,
                                 static_cast<int>(data.size() - off));
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
        }
        const int err = SSL_get_error(impl_->ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            throw std::runtime_error("TlsClient::send: SSL_write err=" +
                                      std::to_string(err));
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("TlsClient::send: timed out after 30s");
        }
        const auto remaining = std::chrono::duration_cast<
            std::chrono::microseconds>(deadline - now).count();
        timeval tv{};
        tv.tv_sec  = remaining / 1'000'000;
        tv.tv_usec = remaining % 1'000'000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(impl_->socket.fd(), &fds);
        const int sel = (err == SSL_ERROR_WANT_READ)
            ? ::select(impl_->socket.fd() + 1, &fds, nullptr, nullptr, &tv)
            : ::select(impl_->socket.fd() + 1, nullptr, &fds, nullptr, &tv);
        if (sel < 0 && errno != EINTR) {
            throw std::runtime_error("TlsClient::send: select failed");
        }
    }
}

std::size_t TlsClient::blocking_read(std::span<std::uint8_t> out, int timeout_ms) {
    if (!impl_->connected) {
        throw std::runtime_error("TlsClient::read: not connected");
    }
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(timeout_ms);
    while (true) {
        const int n = SSL_read(impl_->ssl, out.data(),
                                static_cast<int>(out.size()));
        if (n > 0) return static_cast<std::size_t>(n);
        const int err = SSL_get_error(impl_->ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;   // clean close_notify
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            throw std::runtime_error("TlsClient::read: SSL_read err=" +
                                      std::to_string(err));
        }
        // Wait for fd readiness in the direction OpenSSL asked for.
        // SSL_read can return WANT_WRITE during a renegotiation /
        // post-handshake message — handle both directions.
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        const auto remaining = std::chrono::duration_cast<
            std::chrono::microseconds>(deadline - now).count();
        timeval tv{};
        tv.tv_sec  = remaining / 1'000'000;
        tv.tv_usec = remaining % 1'000'000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(impl_->socket.fd(), &fds);
        const int sel = (err == SSL_ERROR_WANT_READ)
            ? ::select(impl_->socket.fd() + 1, &fds, nullptr, nullptr, &tv)
            : ::select(impl_->socket.fd() + 1, nullptr, &fds, nullptr, &tv);
        if (sel < 0) {
            throw std::runtime_error("TlsClient::read: select failed");
        }
        if (sel == 0) return 0;   // timed out
    }
}

bool TlsClient::is_connected() const noexcept { return impl_->connected; }
int  TlsClient::fd()           const noexcept { return impl_->socket.fd(); }

void TlsClient::close() {
    if (impl_->ssl) {
        SSL_shutdown(impl_->ssl);
        SSL_free(impl_->ssl);
        impl_->ssl = nullptr;
    }
    if (impl_->ctx) {
        SSL_CTX_free(impl_->ctx);
        impl_->ctx = nullptr;
    }
    impl_->socket.close();
    impl_->connected = false;
}

}  // namespace fb::net

#else   // FB_HAVE_OPENSSL == 0

namespace fb::net {

struct TlsClient::Impl {};

TlsClient::TlsClient() : impl_(std::make_unique<Impl>()) {}
TlsClient::~TlsClient() = default;
TlsClient::TlsClient(TlsClient&&) noexcept = default;
TlsClient& TlsClient::operator=(TlsClient&&) noexcept = default;

[[noreturn]] static void unimpl() {
    throw std::runtime_error(
        "TlsClient: OpenSSL not compiled in. Rebuild fb_core (and the "
        "tool that links it) with OpenSSL on the link line so "
        "FB_HAVE_OPENSSL=1 is defined.");
}

void TlsClient::connect(const std::string&, std::uint16_t,
                          const TlsClientOptions&) { unimpl(); }
void TlsClient::blocking_send_all(std::span<const std::uint8_t>) { unimpl(); }
std::size_t TlsClient::blocking_read(std::span<std::uint8_t>, int) { unimpl(); }
bool TlsClient::is_connected() const noexcept { return false; }
int  TlsClient::fd()           const noexcept { return -1; }
void TlsClient::close() {}

}  // namespace fb::net

#endif  // FB_HAVE_OPENSSL
