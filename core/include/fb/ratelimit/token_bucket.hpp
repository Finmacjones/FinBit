// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Per-key token bucket. Used by:
//   - server (centralized phase) to limit per-pubkey ingress
//   - peer relays (P2P phase) to enforce fair-carry on both ends of a flow
// =============================================================================

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>

namespace fb::ratelimit {

class TokenBucket {
public:
    TokenBucket(std::uint64_t rate_bytes_per_sec, std::uint64_t burst_bytes) noexcept
        : rate_(rate_bytes_per_sec),
          burst_(burst_bytes),
          tokens_(static_cast<double>(burst_bytes)),
          last_refill_(std::chrono::steady_clock::now()) {}

    // Attempt to consume `bytes` tokens. Returns true on success.
    bool try_consume(std::uint64_t bytes) noexcept;

    // Inspection.
    [[nodiscard]] double tokens() const noexcept { return tokens_; }
    [[nodiscard]] std::uint64_t rate() const noexcept { return rate_; }
    [[nodiscard]] std::uint64_t burst() const noexcept { return burst_; }

private:
    void refill() noexcept;
    std::uint64_t rate_;
    std::uint64_t burst_;
    double tokens_;
    std::chrono::steady_clock::time_point last_refill_;
};

// Keyed limiter. Key is the binary pubkey (32 bytes for Ed25519).
class KeyedLimiter {
public:
    KeyedLimiter(std::uint64_t rate_bytes_per_sec, std::uint64_t burst_bytes) noexcept
        : rate_(rate_bytes_per_sec), burst_(burst_bytes) {}

    bool try_consume(std::span<const std::uint8_t> key, std::uint64_t bytes);

    // Eviction: remove buckets that are full (no recent activity). Caller
    // periodically calls this to bound memory in long-running servers.
    void evict_full();

    [[nodiscard]] std::size_t tracked_keys() const noexcept { return buckets_.size(); }

private:
    std::uint64_t rate_;
    std::uint64_t burst_;
    std::unordered_map<std::string, TokenBucket> buckets_;
};

}  // namespace fb::ratelimit
