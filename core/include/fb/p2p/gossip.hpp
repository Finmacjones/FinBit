// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Gossip-pubsub on top of the FinBit TCP layer.
//
// Each peer keeps an open TCP connection to every other peer it knows about
// (Phase 5 simplification — production gossipsub limits the active fanout
// per topic to a few peers and uses gossip to fill the gaps). Subscriptions
// and Publish messages flow over those connections.
//
// Anti-flood: every published message carries an envelope-id-style
// `message_id` (16 random bytes). A peer remembers IDs it has seen recently
// and drops duplicates, so the gossip storm terminates after one round of
// fanout. Publishes also carry a TTL; a peer relays only if TTL > 0.
//
// Carry-credit gating: peers consult a callback before relaying a publish
// (so the application can refuse to carry traffic for a peer that owes too
// much). The default permit-all callback is used unless the application
// installs a stricter one.
// =============================================================================

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "fb/p2p/kademlia.hpp"

namespace fb::p2p {

class P2PNode {
public:
    using OnTopicMessage =
        std::function<void(const std::string& topic, std::span<const std::uint8_t> payload,
                           const PeerInfo& origin)>;
    // Carry decision: true to relay, false to drop.
    using CarryGuard = std::function<bool(const PeerInfo& peer, std::uint64_t bytes)>;

    // Construct a node bound to a TCP port. `pubkey` derives the NodeID.
    P2PNode(const std::string& bind_host, std::uint16_t port,
            std::span<const std::uint8_t> pubkey);
    P2PNode(const P2PNode&)            = delete;
    P2PNode& operator=(const P2PNode&) = delete;
    ~P2PNode();

    // Start the listener + IO loop on a worker thread.
    void start();
    void stop();

    // Connect outbound to a peer (typically a bootstrap address).
    void dial(const std::string& host, std::uint16_t port);

    // Subscribe / unsubscribe to a topic. Subscribe is broadcast to all known
    // peers so they fan messages on this topic to us.
    void subscribe(const std::string& topic);
    void unsubscribe(const std::string& topic);

    // Publish to a topic. Sends to every known peer; recipients re-fan to
    // their subscribers (with TTL decrement + dedup).
    void publish(const std::string& topic, std::span<const std::uint8_t> payload,
                 std::uint32_t ttl = 4);

    // Application callbacks.
    void set_on_topic_message(OnTopicMessage cb);
    void set_carry_guard(CarryGuard guard);

    // Diagnostic.
    [[nodiscard]] std::size_t known_peer_count() const;
    [[nodiscard]] NodeId node_id() const noexcept;
    [[nodiscard]] std::string addr() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::p2p
