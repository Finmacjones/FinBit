// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Kademlia routing primitives.
//
// 160-bit address space (matches libp2p PeerID derivation: SHA-256 of the
// identity pubkey, truncated to 20 bytes). Nodes maintain k-buckets indexed
// by the bit-distance between their own NodeID and a peer's NodeID; closer
// peers cluster in low-index buckets, farther peers in high-index buckets.
//
// FinBit Phase 5 uses Kademlia for peer discovery only — the actual message
// fan-out is gossipsub on top (see gossip.hpp). Records (FIND_VALUE / STORE)
// are not used; everything lives in MLS / SenderKeys session state at the
// application layer, not in the DHT.
// =============================================================================

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace fb::p2p {

constexpr std::size_t kNodeIdBytes = 20;
constexpr std::size_t kBucketSize  = 16;  // K
constexpr std::size_t kAddressBits = 8 * kNodeIdBytes;

using NodeId = std::array<std::uint8_t, kNodeIdBytes>;

struct PeerInfo {
    NodeId      id{};
    std::string addr;            // "scheme://host:port"
    // Full Ed25519 pubkey (32 bytes) for this peer when known.
    // Used by overlay transports (DhtSendCallback / GossipSendCallback)
    // to address PeerEnvelopes by recipient_pubkey when the underlying
    // transport routes by pubkey rather than by NodeId. Empty when the
    // pubkey isn't known (e.g. peer learned only via routing-table
    // refresh from a third party). Not used by RoutingTable's bucket
    // ordering — that's still NodeId-based.
    std::vector<std::uint8_t> pubkey;
};

// SHA-256(identity_pubkey)[0..20].
[[nodiscard]] NodeId node_id_from_pubkey(std::span<const std::uint8_t> pubkey);

// XOR distance.
[[nodiscard]] NodeId xor_distance(const NodeId& a, const NodeId& b) noexcept;

// Position of the highest-set bit (0..159). Returns kAddressBits for distance == 0.
[[nodiscard]] std::size_t bucket_index(const NodeId& distance) noexcept;

class RoutingTable {
public:
    explicit RoutingTable(NodeId self) : self_(self), buckets_(kAddressBits) {}

    // Insert / refresh. Returns true if the peer is newly added (was not in
    // table). Self-insertion is silently ignored.
    bool observe(const PeerInfo& peer);

    // Up-to-`limit` peers ordered by ascending XOR-distance from `target`.
    [[nodiscard]] std::vector<PeerInfo> closest(const NodeId& target, std::size_t limit) const;

    // All known peers, in no particular order.
    [[nodiscard]] std::vector<PeerInfo> all() const;

    [[nodiscard]] const NodeId& self_id() const noexcept { return self_; }
    [[nodiscard]] std::size_t   size() const noexcept;

private:
    NodeId self_;
    // Each bucket: peers ordered by least-recently-seen at the front.
    std::vector<std::vector<PeerInfo>> buckets_;
};

}  // namespace fb::p2p
