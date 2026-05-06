// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// P2P / decentralized substrate — Phase 5 scaffolding.
//
// FinBit transitions from server-mediated to peer-to-peer at
// fb::config::kDecentralizationThreshold (10,000 active users). Crucially,
// the wire protocol does NOT change — the same `Envelope` flows over either
// transport. Only the routing layer differs.
//
// PHASE 0 STATUS: stubs throw. Phase 5 implements with cpp-libp2p
// (Soramitsu) by default, fallback to libtorrent's DHT + a thin gossip
// layer over Asio if cpp-libp2p proves unworkable. The interface below is
// strict enough that swapping is mechanical:
//   - IP2PHost owns lifecycle and identity
//   - IDiscovery wraps Kademlia FIND_NODE / PROVIDE
//   - IPubSub wraps gossipsub for channel-fan-out + presence broadcasts
//
// Fair-usage: every relay hop in this layer must consult the same
// fb::ratelimit::KeyedLimiter that the centralized server does. The
// per-pubkey accounting is identical; only the deciding peer differs. The
// Phase 5 carry-credit ledger (already present in fb::store::SqliteStore::
// record_carry / carry_balance) gates relay decisions.
// =============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace fb::p2p {

class IDiscovery {
public:
    virtual ~IDiscovery() = default;
    // Find peers responsible for serving messages addressed to `key`.
    [[nodiscard]] virtual std::vector<std::string> find_providers(
        std::span<const std::uint8_t> key) = 0;
    // Announce that we serve messages for `key`.
    virtual void provide(std::span<const std::uint8_t> key) = 0;
};

class IPubSub {
public:
    using OnMessage = std::function<void(std::span<const std::uint8_t> data)>;
    virtual ~IPubSub() = default;
    virtual void subscribe(const std::string& topic, OnMessage cb) = 0;
    virtual void publish(const std::string& topic, std::span<const std::uint8_t> data) = 0;
};

class IP2PHost {
public:
    virtual ~IP2PHost() = default;

    // Boot the host. `bootstrap_multiaddrs` are the entry points (typically
    // the centralized fb_server in its bootstrap-node mode plus any well-known
    // community peers).
    virtual bool start(const std::vector<std::string>& bootstrap_multiaddrs) = 0;
    virtual void stop() = 0;

    [[nodiscard]] virtual IDiscovery& discovery() = 0;
    [[nodiscard]] virtual IPubSub&    pubsub()    = 0;

    // Returns this host's libp2p PeerId (usually base58-encoded).
    [[nodiscard]] virtual std::string peer_id() const = 0;
};

[[nodiscard]] std::unique_ptr<IP2PHost> make_p2p_host(std::span<const std::uint8_t, 32> identity_priv);

}  // namespace fb::p2p
