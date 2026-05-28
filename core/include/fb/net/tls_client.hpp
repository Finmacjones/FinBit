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
#include <vector>

namespace fb::net {

// TLS ClientHello fingerprint profile (Tier-4 censorship mimicry).
//
// JA3/JA4 DPI classifies a TLS client by the cipher-suite list, the
// supported-groups (curves) list, the signature-algorithm list and the
// extension layout in the ClientHello. Stock OpenSSL's defaults differ
// from any browser, so even a perfect SNI/ALPN/HTTP-upgrade still flags
// as "not a browser". Selecting kChrome / kFirefox reshapes the cipher,
// group and sigalg lists to match that browser's order.
//
// HONEST LIMIT: OpenSSL does not expose TLS-extension ordering or
// client-side GREASE injection, so the resulting JA3 matches a browser
// in the cipher/group/sigalg fields but NOT byte-for-byte in the
// extension field. Byte-perfect uTLS-grade mimicry needs BoringSSL or
// a custom ClientHello assembler; SNI encryption needs ECH. See
// docs/censorship-resistance.md (Tier 4).
enum class TlsFingerprint { kDefault, kChrome, kFirefox };

struct TlsClientOptions {
    // CA file (PEM) used to validate the server cert. If empty, the
    // system CA bundle is used (SSL_CTX_set_default_verify_paths).
    std::string ca_file;

    // Optional SOCKS5 proxy ("host:port") to route the underlying TCP
    // connection through. Combined with a local Tor instance running with
    // obfs4/Snowflake bridges (torrc), this is FinBit's hostile-network
    // transport: the ISP sees obfs4-looking traffic to a bridge instead of
    // a TLS connection to the relay. Empty = direct TCP. The TLS handshake
    // runs unchanged over the SOCKS5 tunnel; SNI / cert validation are
    // bound to the TARGET host, not the proxy.
    std::string socks5_proxy;

    // Disable cert validation entirely. Strictly for local dev / CI where
    // a self-signed cert is acceptable; warn-on-use logged from the cli.
    bool insecure_skip_verify = false;

    // SNI hostname sent during the handshake. Defaults to the connect
    // host. Override when the server's cert CN/SAN differs from the IP
    // you're dialing (common for CDN / cert-pinned setups).
    std::string sni_hostname;

    // ---- ALPN (censorship-resistance: TLS-on-443 mimicry) ----
    //
    // Application-Layer Protocol Negotiation list advertised in the
    // ClientHello. A browser ALWAYS sends ALPN; a TLS client that
    // sends none is trivially fingerprintable. We default to
    // {"http/1.1"} because that's what we genuinely speak on top
    // (the WebSocket upgrade and the DoH GET are both HTTP/1.1).
    //
    // NB: we deliberately do NOT advertise "h2" by default — if a
    // third-party server (e.g. a public DoH endpoint) selected h2 we
    // would have to speak HTTP/2 framing, which we don't. Offering
    // only protocols we can actually speak keeps us correct. Set to
    // an empty vector to suppress the ALPN extension entirely.
    // See docs/censorship-resistance.md (Tier 2).
    std::vector<std::string> alpn_protocols{"http/1.1"};

    // ClientHello fingerprint profile (Tier-4). Default kDefault keeps
    // OpenSSL's native ClientHello; kChrome / kFirefox reshape the
    // cipher / group / sigalg lists toward that browser's JA3.
    TlsFingerprint tls_fingerprint = TlsFingerprint::kDefault;

    // ECH (Encrypted Client Hello) config — the server's ECHConfigList
    // wire bytes (e.g. from a DNS `ech=` value via the DoH path; decode
    // with fb::net::ech::decode_ech_config_list_b64). When set AND the
    // TLS stack supports ECH (FB_HAVE_ECH=1), the SNI is encrypted to
    // this config; otherwise it's ignored (cleartext SNI). See
    // docs/censorship-resistance.md (Tier 4).
    std::vector<std::uint8_t> ech_config_list;

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

// Diagnostic / testing: produce the raw TLS ClientHello bytes this
// client would put on the wire for the given fingerprint profile, using
// an in-memory BIO (no socket, no peer). Lets tests verify the JA3
// shaping (cipher-suite / supported-group order) deterministically.
// Returns an empty vector if OpenSSL isn't compiled in.
[[nodiscard]] std::vector<std::uint8_t> debug_client_hello(TlsFingerprint fp);

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
