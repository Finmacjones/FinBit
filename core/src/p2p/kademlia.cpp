// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/kademlia.hpp"

#include <sodium.h>

#include <algorithm>
#include <stdexcept>

namespace fb::p2p {

NodeId node_id_from_pubkey(std::span<const std::uint8_t> pubkey) {
    static const int rc = sodium_init();
    if (rc < 0) throw std::runtime_error("libsodium init failed");
    std::array<std::uint8_t, crypto_hash_sha256_BYTES> full{};
    if (crypto_hash_sha256(full.data(), pubkey.data(), pubkey.size()) != 0) {
        throw std::runtime_error("crypto_hash_sha256 failed");
    }
    NodeId out{};
    std::copy_n(full.begin(), kNodeIdBytes, out.begin());
    return out;
}

NodeId xor_distance(const NodeId& a, const NodeId& b) noexcept {
    NodeId out{};
    for (std::size_t i = 0; i < kNodeIdBytes; ++i) {
        out[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return out;
}

std::size_t bucket_index(const NodeId& distance) noexcept {
    for (std::size_t i = 0; i < kNodeIdBytes; ++i) {
        if (distance[i] == 0) continue;
        // Find the position of the highest bit in this byte.
        for (int bit = 7; bit >= 0; --bit) {
            if ((distance[i] >> bit) & 1U) {
                const std::size_t bytes_remaining = kNodeIdBytes - 1 - i;
                return bytes_remaining * 8 + static_cast<std::size_t>(bit);
            }
        }
    }
    return kAddressBits;  // distance == 0 (self)
}

bool RoutingTable::observe(const PeerInfo& peer) {
    if (peer.id == self_) return false;
    const auto idx = bucket_index(xor_distance(self_, peer.id));
    if (idx >= buckets_.size()) return false;
    auto& b = buckets_[idx];
    auto it = std::find_if(b.begin(), b.end(),
                           [&](const PeerInfo& p) { return p.id == peer.id; });
    if (it != b.end()) {
        // Refresh: move to most-recently-seen end.
        PeerInfo p = std::move(*it);
        b.erase(it);
        // Update address in case it changed.
        p.addr = peer.addr;
        b.push_back(std::move(p));
        return false;
    }
    if (b.size() < kBucketSize) {
        b.push_back(peer);
        return true;
    }
    // Bucket full — evict oldest (least-recently-seen). A real Kademlia would
    // PING the candidate first; Phase 0 keeps it simple.
    b.front() = peer;
    return true;
}

std::vector<PeerInfo> RoutingTable::closest(const NodeId& target, std::size_t limit) const {
    // Naive O(N log N) — fine for a routing table holding at most K * 160 peers.
    std::vector<PeerInfo> all_peers = all();
    std::sort(all_peers.begin(), all_peers.end(),
              [&](const PeerInfo& a, const PeerInfo& b) {
                  return xor_distance(a.id, target) < xor_distance(b.id, target);
              });
    if (all_peers.size() > limit) all_peers.resize(limit);
    return all_peers;
}

std::vector<PeerInfo> RoutingTable::all() const {
    std::vector<PeerInfo> out;
    out.reserve(size());
    for (const auto& b : buckets_) {
        for (const auto& p : b) out.push_back(p);
    }
    return out;
}

std::size_t RoutingTable::size() const noexcept {
    std::size_t n = 0;
    for (const auto& b : buckets_) n += b.size();
    return n;
}

}  // namespace fb::p2p
