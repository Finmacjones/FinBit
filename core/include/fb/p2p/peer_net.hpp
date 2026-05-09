// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

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

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace fb::p2p {

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
