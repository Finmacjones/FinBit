// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/ratelimit/token_bucket.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

namespace fb::ratelimit {

void TokenBucket::refill() noexcept {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - last_refill_).count();
    if (elapsed_ns <= 0) return;
    const double added = (static_cast<double>(rate_) * static_cast<double>(elapsed_ns)) / 1e9;
    tokens_ = std::min<double>(tokens_ + added, static_cast<double>(burst_));
    last_refill_ = now;
}

bool TokenBucket::try_consume(std::uint64_t bytes) noexcept {
    refill();
    if (tokens_ + 1e-9 < static_cast<double>(bytes)) return false;
    tokens_ -= static_cast<double>(bytes);
    return true;
}

bool KeyedLimiter::try_consume(std::span<const std::uint8_t> key, std::uint64_t bytes) {
    std::string k(reinterpret_cast<const char*>(key.data()), key.size());
    auto it = buckets_.find(k);
    if (it == buckets_.end()) {
        it = buckets_.emplace(std::move(k), TokenBucket(rate_, burst_)).first;
    }
    return it->second.try_consume(bytes);
}

void KeyedLimiter::evict_full() {
    for (auto it = buckets_.begin(); it != buckets_.end();) {
        // Force a refill, then drop if at full burst (no recent traffic).
        if (it->second.try_consume(0) && it->second.tokens() >= static_cast<double>(burst_) - 1.0) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace fb::ratelimit
