// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/tls_client.hpp"

#include "fb/net/tcp.hpp"

#include <chrono>
#include <stdexcept>

#if FB_HAVE_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <sys/select.h>
#  include <unistd.h>
#endif

namespace fb::net {
namespace {

// Wait for socket readiness on POSIX or Windows. Returns >0 if the
// socket became ready in the requested direction, 0 on timeout, <0
// on error (EINTR handled internally so the caller can treat any
// negative return as fatal).
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
    } else if (opts.expected_peer_pubkey_set) {
        // Pinned-pubkey mode: the chain check would fail (peer cert
        // is self-signed at the identity key) so we skip it here and
        // do the cryptographic verification at the application layer
        // after the handshake completes.
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

    // Optional client cert (mutual-TLS for serverless P2P). Loaded
    // from in-memory PEM strings — no temp-file dance.
    if (!opts.client_cert_pem.empty() && !opts.client_key_pem.empty()) {
        BIO* cbio = BIO_new_mem_buf(opts.client_cert_pem.data(),
                                     static_cast<int>(opts.client_cert_pem.size()));
        if (!cbio) throw_openssl("BIO_new_mem_buf(client_cert_pem)");
        X509* ccert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
        BIO_free(cbio);
        if (!ccert) throw_openssl("PEM_read_bio_X509(client_cert_pem)");
        if (SSL_CTX_use_certificate(impl_->ctx, ccert) != 1) {
            X509_free(ccert);
            throw_openssl("SSL_CTX_use_certificate");
        }
        X509_free(ccert);

        BIO* kbio = BIO_new_mem_buf(opts.client_key_pem.data(),
                                     static_cast<int>(opts.client_key_pem.size()));
        if (!kbio) throw_openssl("BIO_new_mem_buf(client_key_pem)");
        EVP_PKEY* ckey = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
        BIO_free(kbio);
        if (!ckey) throw_openssl("PEM_read_bio_PrivateKey(client_key_pem)");
        if (SSL_CTX_use_PrivateKey(impl_->ctx, ckey) != 1) {
            EVP_PKEY_free(ckey);
            throw_openssl("SSL_CTX_use_PrivateKey");
        }
        EVP_PKEY_free(ckey);
    }

    // 2. TCP connect.
    impl_->socket = tcp_connect(host, port);

    // 3. SSL object. Bind it to the socket fd.
    impl_->ssl = SSL_new(impl_->ctx);
    if (!impl_->ssl) throw_openssl("SSL_new");
    if (SSL_set_fd(impl_->ssl, impl_->socket.fd()) != 1) {
        throw_openssl("SSL_set_fd");
    }

    // 3b. ALPN. Browsers always advertise ALPN; a TLS ClientHello with
    // no ALPN extension is a cheap fingerprint. Encode the protocol
    // list in the wire format OpenSSL wants: a sequence of
    // length-prefixed strings (1-byte length + bytes). Empty list =>
    // suppress the extension.
    if (!opts.alpn_protocols.empty()) {
        std::vector<unsigned char> wire;
        for (const auto& p : opts.alpn_protocols) {
            if (p.empty() || p.size() > 255) continue;
            wire.push_back(static_cast<unsigned char>(p.size()));
            wire.insert(wire.end(), p.begin(), p.end());
        }
        if (!wire.empty()) {
            // Returns 0 on success (note: inverted vs most OpenSSL APIs).
            if (SSL_set_alpn_protos(impl_->ssl, wire.data(),
                                    static_cast<unsigned int>(wire.size())) != 0) {
                throw_openssl("SSL_set_alpn_protos");
            }
        }
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
        const int sel = wait_socket_ready(
            impl_->socket.fd(),
            err == SSL_ERROR_WANT_READ,
            err == SSL_ERROR_WANT_WRITE,
            static_cast<std::int64_t>(remaining));
        if (sel < 0) {
            throw std::runtime_error(
                "TlsClient handshake wait_socket_ready failed");
        }
        // sel == 0 (timed out) → loop will re-check deadline and bail.
    }

    impl_->connected = true;

    // Optional pinned-pubkey check: extract the peer's Ed25519 key
    // from the cert they presented and require it equals the bytes
    // the caller specified. Used for direct-P2P dials where we know
    // exactly which peer we're trying to reach (from a DHT lookup).
    if (opts.expected_peer_pubkey_set) {
        X509* peer_cert = SSL_get_peer_certificate(impl_->ssl);
        if (!peer_cert) {
            throw std::runtime_error(
                "TlsClient: expected_peer_pubkey set but peer "
                "presented no cert");
        }
        EVP_PKEY* pkey = X509_get_pubkey(peer_cert);
        bool ok = false;
        if (pkey && EVP_PKEY_id(pkey) == EVP_PKEY_ED25519) {
            std::array<std::uint8_t, 32> got{};
            std::size_t len = got.size();
            if (EVP_PKEY_get_raw_public_key(pkey, got.data(), &len) == 1 &&
                len == 32) {
                ok = std::equal(got.begin(), got.end(),
                                opts.expected_peer_pubkey.begin());
            }
        }
        if (pkey) EVP_PKEY_free(pkey);
        X509_free(peer_cert);
        if (!ok) {
            throw std::runtime_error(
                "TlsClient: peer cert pubkey did not match "
                "expected_peer_pubkey (identity-pin failure)");
        }
    }
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
        const int sel = wait_socket_ready(
            impl_->socket.fd(),
            err == SSL_ERROR_WANT_READ,
            err == SSL_ERROR_WANT_WRITE,
            static_cast<std::int64_t>(remaining));
        if (sel < 0) {
            throw std::runtime_error("TlsClient::send: wait_socket_ready failed");
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
        const int sel = wait_socket_ready(
            impl_->socket.fd(),
            err == SSL_ERROR_WANT_READ,
            err == SSL_ERROR_WANT_WRITE,
            static_cast<std::int64_t>(remaining));
        if (sel < 0) {
            throw std::runtime_error("TlsClient::read: wait_socket_ready failed");
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
