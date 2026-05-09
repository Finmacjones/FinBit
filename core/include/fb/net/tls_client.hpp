// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// TLS client wrapper.
//
// Wraps an outbound TCP socket with OpenSSL so the rest of the wire format
// (length-prefixed `Frame` protobufs) flows over a TLS-encrypted transport.
// This is the client-side analog of the server's --tls-port mode.
//
// Why "TLS-wrapped raw" rather than full WSS:
//   - The desktop client speaks raw framed protobufs over TCP. Wrapping that
//     transport in TLS gives us:
//       * end-to-end network confidentiality / integrity
//       * deterministic-looking traffic on a chosen port (e.g. 443)
//       * cert-pinned server identity verification
//   - We DON'T need full WebSocket framing (browsers go through the
//     server's separate --tls-port WSS stack).
//
// Build-time switch: only compiled when FB_HAVE_OPENSSL=1 is defined. Without
// OpenSSL, callers see the throwing stub variant — same as the server's
// existing pattern. The stub variant builds so call sites compile
// unconditionally.
//
// Threading: a single TlsClient is single-threaded. Callers that want
// concurrent read+write must serialize access externally.
// =============================================================================

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace fb::net {

struct TlsClientOptions {
    // CA file (PEM) used to validate the server cert. If empty, the
    // system CA bundle is used (SSL_CTX_set_default_verify_paths).
    std::string ca_file;

    // Disable cert validation entirely. Strictly for local dev / CI where
    // a self-signed cert is acceptable; warn-on-use logged from the cli.
    bool insecure_skip_verify = false;

    // SNI hostname sent during the handshake. Defaults to the connect
    // host. Override when the server's cert CN/SAN differs from the IP
    // you're dialing (common for CDN / cert-pinned setups).
    std::string sni_hostname;

    // ---- Identity-pinned mutual auth (FinBit serverless P2P) ----
    //
    // When set, present this client cert + key during the TLS
    // handshake. PeerNet uses this to attest to the dialing peer's
    // Ed25519 identity at the TLS layer. PEM strings (NOT file
    // paths) so callers can hold the material in memory without
    // touching disk.
    std::string client_cert_pem;
    std::string client_key_pem;

    // When set, after the handshake we extract the peer's Ed25519
    // pubkey from their cert and verify it matches these 32 bytes.
    // Mismatch → connect() throws. Used by direct-P2P dials where
    // we expect a specific peer identity (e.g. from a DHT lookup).
    // Empty = no pubkey check; the existing CA-based chain check
    // still runs (or insecure_skip_verify bypasses it).
    std::array<std::uint8_t, 32> expected_peer_pubkey{};
    bool                          expected_peer_pubkey_set = false;
};

class TlsClient {
public:
    TlsClient();
    ~TlsClient();
    TlsClient(const TlsClient&)            = delete;
    TlsClient& operator=(const TlsClient&) = delete;
    TlsClient(TlsClient&& o) noexcept;
    TlsClient& operator=(TlsClient&& o) noexcept;

    // Connect + complete the TLS handshake against host:port. Throws on
    // any failure (connect, handshake, cert validation). On success the
    // client is ready for read_some / write_some / blocking_send /
    // blocking_recv.
    void connect(const std::string& host, std::uint16_t port,
                  const TlsClientOptions& opts = {});

    // Blocking write of every byte in `data`. Throws on permanent error.
    void blocking_send_all(std::span<const std::uint8_t> data);

    // Blocking read of up to out.size() bytes. Returns the number actually
    // read, or 0 on clean shutdown. Throws on permanent error.
    std::size_t blocking_read(std::span<std::uint8_t> out, int timeout_ms);

    [[nodiscard]] bool is_connected() const noexcept;

    // Underlying socket fd (so callers using select/poll can wait on it).
    [[nodiscard]] int fd() const noexcept;

    void close();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::net
