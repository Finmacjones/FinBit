// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Cert-pinning convention
// =============================================================================
//
// PeerNet's outbound side ALWAYS pins the dialed peer's identity Ed25519
// pubkey via TlsClientOptions::expected_peer_pubkey when peer.pubkey is
// populated. The TLS handshake fails (and the connection is dropped before
// any application bytes flow) if the cert the remote presents doesn't
// match — see TlsClient::connect's "identity-pin failure" throw site.
//
// To make the pin explicit at the URL layer too — useful when an addr is
// shared out-of-band (QR code, bootstrap file) and you want the recipient
// to see the binding without separately checking pubkey bytes — addr
// strings MAY include a fragment of the form
//
//     wss://host:port#<lowercase-hex-32-bytes>
//
// where the hex section is the SHA-256(...)[0..32] of the identity pubkey,
// or the pubkey itself. parse_pinned_addr() below splits the fragment
// from the connect target so the dialer can sanity-check it against
// peer.pubkey before opening the socket. The fragment is NEVER sent over
// the wire.
//
// =============================================================================
// PeerNet — direct peer-to-peer TLS transport.
//
// This is the pure-P2P transport that complements (and eventually
// replaces) the server-relayed PeerEnvelope path in chat_client. Each
// FinBit instance can:
//
//   - LISTEN on a TLS-wrapped TCP port for inbound peer connections
//     (start_listener).
//   - DIAL OUT to other peers via TlsClient (send) and pool the
//     resulting connections so subsequent sends to the same peer
//     reuse the channel.
//
// Wire format on PeerNet connections is length-prefixed bytes
// (fb::net::encode_frame / FrameDecoder). The bytes are opaque to
// PeerNet — caller (ChatClient) wraps them in a Frame.peer envelope
// before send so the inbound dispatch path is the same one used by
// the server-relayed transport.
//
// Threading:
//   - PeerNet spawns one thread per outbound connection and one per
//     accepted inbound connection (plus one thread for the accept
//     loop). All threads use blocking I/O with short timeouts.
//   - on_message is invoked from the worker threads. Callers MUST
//     either serialize internally or forward the bytes onto a
//     single dispatch thread (chat_client does the latter via a
//     thread-safe inbound queue).
//
// Build-time switch: only compiled when FB_HAVE_OPENSSL=1. The stub
// variant throws on every public method (matches TlsClient's
// fallback shape). Without OpenSSL the rest of the codebase still
// builds — peer-to-peer mode is just unavailable.
// =============================================================================

#include "fb/p2p/kademlia.hpp"
#include "fb/net/tls_client.hpp"   // fb::net::TlsFingerprint

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace fb::p2p {

// Split "wss://host:port#hexfingerprint" into its connect target and the
// optional pinned fingerprint. The fragment is treated as raw bytes (not
// hex-decoded by this function) for caller-side comparison flexibility.
// Returns the addr without the fragment + the hex fragment string (empty
// if none). Doesn't validate the fragment shape — callers can require
// 64-char-hex / specific encoding rules as they like.
struct PinnedAddr {
    std::string addr_without_fragment;
    std::string pin_fragment_hex;   // empty if no '#' was present
};
[[nodiscard]] PinnedAddr parse_pinned_addr(const std::string& addr);

struct PeerListenerOptions {
    std::string bind_host = "0.0.0.0";
    // 0 = let the kernel pick a free port; query listener_port()
    // afterwards to find what was actually bound (used in tests).
    std::uint16_t bind_port = 0;
    // PEM file paths for the listener's TLS identity.
    std::string tls_cert_pem;
    std::string tls_key_pem;
    // Mutual auth: when true, connecting peers MUST present a client
    // cert during the TLS handshake. Recommended for the serverless
    // P2P path (PeerNet's main use case) — the listener extracts the
    // client's Ed25519 pubkey from the cert and exposes it on
    // PeerInfo.pubkey, giving downstream code (DhtNode etc.)
    // TLS-attested peer identity instead of a self-stamped sender
    // pubkey field.
    //
    // Default false for backwards compatibility with anonymous-dial
    // callers; the cert pubkey is still extracted whenever a peer
    // happens to present one.
    bool require_client_cert = false;
};

struct PeerDialerOptions {
    // PEM CA bundle; empty = system trust store. Same semantics as
    // TlsClientOptions::ca_file.
    std::string ca_file;
    // Skip cert validation entirely. Dev / self-signed only.
    bool insecure_skip_verify = false;
    // ---- Mutual auth (FinBit serverless P2P) ----
    // PEM-encoded identity cert + key to present during outbound
    // handshakes. Use fb::crypto::generate_identity_cert() to derive
    // them from an Ed25519 seed.
    std::string client_cert_pem;
    std::string client_key_pem;

    // Censorship-resistance (Tier 2). When true, after the TLS
    // handshake the dialer performs an RFC 6455 WebSocket upgrade and
    // frames all traffic as masked WS binary messages, so a P2P link
    // is wire-indistinguishable from a browser's WSS. The listener
    // auto-detects WS vs raw per inbound connection, so a WSS dialer
    // interoperates with any listener (and a raw dialer with a
    // WSS-capable listener). Default false keeps the raw
    // frames-over-TLS behaviour. See docs/censorship-resistance.md.
    bool wss = false;

    // Tier-3 domain-fronting (only meaningful with wss=true). When
    // non-empty, front_sni overrides the TLS SNI sent on outbound dials
    // (the front domain a censor sees) and ws_host_header sets the WS
    // Host header (the real backend a fronting CDN / reverse-proxy
    // routes to). Both are independent of the dialed connect address.
    // Empty => SNI and Host both default to the dialed host (no
    // fronting). NB: a single front applies to ALL outbound dials, so
    // PeerNet fronting suits a fixed-front deployment, not per-peer
    // CDN routing.
    std::string front_sni;
    std::string ws_host_header;

    // Tier-4: ClientHello fingerprint for outbound dials. Default
    // kDefault; set kChrome/kFirefox to shape the JA3 toward a browser.
    fb::net::TlsFingerprint tls_fingerprint = fb::net::TlsFingerprint::kDefault;
};

class PeerNet {
public:
    using OnMessage =
        std::function<void(const PeerInfo& from,
                           std::span<const std::uint8_t> bytes)>;

    PeerNet();
    ~PeerNet();
    PeerNet(const PeerNet&)            = delete;
    PeerNet& operator=(const PeerNet&) = delete;

    // Start accepting inbound connections. Optional — peers that
    // only dial out (typical NATed clients) don't need this. Throws
    // on bind / TLS context failure.
    void start_listener(const PeerListenerOptions& opts);

    // Port we actually ended up bound to (useful when bind_port=0).
    // Returns 0 if no listener is running.
    [[nodiscard]] std::uint16_t listener_port() const noexcept;

    // Configure outbound TLS. Call before the first send().
    void set_dialer(const PeerDialerOptions& opts);

    // Inbound dispatch. Called from PeerNet's per-connection
    // worker threads — NOT thread-safe with respect to itself.
    // Caller is responsible for serialising into a single thread
    // if downstream consumers (DhtNode / UsernameGossip) require it.
    void set_on_message(OnMessage cb);

    // Send framed bytes to the peer. Dials via TlsClient if we
    // don't already have a connection for peer.addr; reuses the
    // existing connection otherwise. Returns true on enqueue,
    // false if peer.addr is unparseable or empty.
    //
    // peer.addr format: "wss://host:port" — only TLS is supported
    // by PeerNet (the whole point is to look like web traffic on
    // 443). Plain TCP is intentionally not implemented.
    bool send(const PeerInfo& peer,
              std::span<const std::uint8_t> bytes);

    // Stop everything: close listener, signal workers, join. Called
    // automatically from the destructor; expose for explicit early
    // teardown when the owning ChatClient disconnects.
    void shutdown();

    // Diagnostics.
    [[nodiscard]] std::size_t outbound_count() const;
    [[nodiscard]] std::size_t inbound_count()  const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::p2p
