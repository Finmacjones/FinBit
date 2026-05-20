// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/tls_client.hpp"

#include "fb/net/tcp.hpp"

#include <chrono>
#include <stdexcept>

#if FB_HAVE_OPENSSL

#include <openssl/err.h>
#include <openssl/rand.h>
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

// --- GREASE (RFC 8701) -----------------------------------------------------
// Browsers inject GREASE values to keep the ecosystem tolerant of unknown
// TLS codepoints; their absence is itself a fingerprint. OpenSSL has no
// client GREASE of its own, but SSL_CTX_add_custom_ext lets us add
// extensions with GREASE type values, which moves the JA3/JA4 extension
// list toward a browser's. (Cipher/group/version GREASE still needs
// BoringSSL — see docs/censorship-resistance.md Tier 4.)
constexpr std::uint16_t kGreaseValues[16] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

int grease_ext_add(SSL*, unsigned int, unsigned int,
                   const unsigned char** out, std::size_t* outlen,
                   X509*, std::size_t, int*, void*) {
    static const unsigned char kEmpty = 0;
    *out = &kEmpty;   // ignored when *outlen == 0
    *outlen = 0;      // empty GREASE extension body
    return 1;         // 1 = include the extension
}
void grease_ext_free(SSL*, unsigned int, unsigned int,
                     const unsigned char*, void*) {}

// Apply a browser ClientHello fingerprint profile (Tier-4). Best-effort:
// names that a particular OpenSSL build doesn't recognise are skipped so
// the handshake still works — shaping degrades gracefully rather than
// failing the connection.
void apply_fingerprint(SSL_CTX* ctx, TlsFingerprint fp) {
    if (fp == TlsFingerprint::kDefault) return;

    // TLS 1.3 ciphersuites (order matters for JA3).
    const char* suites13 = nullptr;
    // TLS 1.2 cipher list (OpenSSL cipher-string names, in order).
    const char* ciphers12 = nullptr;
    // Supported groups (curves) and signature algorithms, in order.
    const char* groups = nullptr;
    const char* sigalgs = nullptr;

    if (fp == TlsFingerprint::kChrome) {
        suites13 = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                   "TLS_CHACHA20_POLY1305_SHA256";
        ciphers12 =
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
            "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
        groups  = "X25519:P-256:P-384";
        sigalgs = "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:"
                  "ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:"
                  "RSA-PSS+SHA512:RSA+SHA512";
    } else {  // kFirefox
        suites13 = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:"
                   "TLS_AES_256_GCM_SHA384";
        ciphers12 =
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
            "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
        // Firefox advertises FFDHE groups too (OpenSSL 3.0+); harmless
        // if a name is unknown — set1_groups_list fails and we keep the
        // default groups for that field.
        groups  = "X25519:P-256:P-384:ffdhe2048:ffdhe3072";
        sigalgs = "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:"
                  "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:"
                  "RSA+SHA256:RSA+SHA384:RSA+SHA512";
    }

    // Each call is best-effort; clear the error queue on failure so a
    // skipped knob doesn't poison a later real error.
    if (suites13)  { if (SSL_CTX_set_ciphersuites(ctx, suites13) != 1) ERR_clear_error(); }
    if (ciphers12) { if (SSL_CTX_set_cipher_list(ctx, ciphers12) != 1) ERR_clear_error(); }
    if (groups)    { if (SSL_CTX_set1_groups_list(ctx, groups) != 1)   ERR_clear_error(); }
    if (sigalgs)   { if (SSL_CTX_set1_sigalgs_list(ctx, sigalgs) != 1)  ERR_clear_error(); }

    // Add two distinct GREASE extensions (like a browser's first/last
    // GREASE). Random per-connection — TlsClient builds a fresh CTX per
    // connect, so each handshake picks fresh values.
    std::uint8_t r[2] = {0, 0};
    if (RAND_bytes(r, 2) == 1) {
        const std::uint16_t g1 = kGreaseValues[r[0] & 0x0f];
        std::uint16_t g2 = kGreaseValues[r[1] & 0x0f];
        if (g2 == g1) g2 = kGreaseValues[(r[1] + 1) & 0x0f];
        for (std::uint16_t g : {g1, g2}) {
            if (SSL_CTX_add_custom_ext(
                    ctx, g, SSL_EXT_CLIENT_HELLO,
                    grease_ext_add, grease_ext_free, nullptr,
                    nullptr, nullptr) != 1) {
                ERR_clear_error();
            }
        }
    }
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

    // Tier-4: reshape cipher/group/sigalg lists toward a browser JA3.
    apply_fingerprint(impl_->ctx, opts.tls_fingerprint);

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

    // 3c. ECH (Encrypted Client Hello). Only compiled when the TLS stack
    // exposes the hooks (FB_HAVE_ECH); otherwise the config is ignored
    // and the SNI travels in cleartext (Tiers 2/3 still apply). When
    // active, OpenSSL HPKE-encrypts the real SNI to the server's
    // published config, so a passive observer sees only the outer
    // public name.
#if FB_HAVE_ECH
    if (!opts.ech_config_list.empty()) {
        if (SSL_set1_ech_config_list(impl_->ssl,
                                     opts.ech_config_list.data(),
                                     opts.ech_config_list.size()) != 1) {
            ERR_clear_error();  // best-effort: fall back to cleartext SNI
        }
    }
#endif

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

std::vector<std::uint8_t> debug_client_hello(TlsFingerprint fp) {
    openssl_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return {};
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    apply_fingerprint(ctx, fp);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return {}; }
    // Memory BIOs: SSL writes the ClientHello into wbio; rbio stays
    // empty so the handshake parks at WANT_READ after the first flight.
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);   // takes ownership of both
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, "example.com");
    (void)SSL_do_handshake(ssl);    // emits ClientHello, then WANT_READ

    std::vector<std::uint8_t> out;
    char buf[4096];
    int n;
    while ((n = BIO_read(wbio, buf, static_cast<int>(sizeof(buf)))) > 0) {
        out.insert(out.end(), buf, buf + n);
    }
    SSL_free(ssl);     // frees rbio + wbio
    SSL_CTX_free(ctx);
    return out;
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

std::vector<std::uint8_t> debug_client_hello(TlsFingerprint) { return {}; }

}  // namespace fb::net

#endif  // FB_HAVE_OPENSSL
