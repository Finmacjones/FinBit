// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/room_keys.hpp"

#include <cstring>

#include "fb/media/sframe.hpp"

namespace fb::media {

namespace {
std::span<const std::uint8_t> as_bytes(std::string_view s) {
    return std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}
}  // namespace

RoomKeyRegistry::RoomKeyRegistry(std::array<std::uint8_t, 32> my_pubkey,
                                 std::chrono::milliseconds grace, Clock clock)
    : my_pubkey_(my_pubkey), grace_(grace), clock_(std::move(clock)) {}

std::chrono::steady_clock::time_point RoomKeyRegistry::now() const {
    return clock_ ? clock_() : std::chrono::steady_clock::now();
}

void RoomKeyRegistry::set_secret(std::span<const std::uint8_t, 32> secret,
                                 std::uint32_t epoch) {
    std::lock_guard<std::mutex> lk(mu_);
    if (has_ && epoch <= cur_epoch_) return;   // stale or duplicate → ignore

    if (has_) {
        // Retire the current secret into the grace slot so trailing frames
        // sealed at the old epoch keep opening for a short window.
        prev_secret_ = cur_secret_;
        prev_epoch_  = cur_epoch_;
        has_prev_    = true;
        prev_until_  = now() + grace_;
    }

    std::memcpy(cur_secret_.data(), secret.data(), cur_secret_.size());
    cur_epoch_ = epoch;
    has_       = true;

    // Precompute K_self so the per-frame seal path is a plain copy, not an
    // HKDF each frame.
    cur_seal_.epoch = cur_epoch_;
    cur_seal_.key   = derive_room_sframe_key(
        std::span<const std::uint8_t, 32>(cur_secret_.data(), 32),
        as_bytes(std::string_view(
            reinterpret_cast<const char*>(my_pubkey_.data()), my_pubkey_.size())),
        cur_epoch_);

    // Drop cache entries for epochs we no longer accept (keep cur + prev).
    for (auto it = cache_.begin(); it != cache_.end();) {
        const std::uint32_t e = it->first.second;
        const bool keep = (e == cur_epoch_) || (has_prev_ && e == prev_epoch_);
        if (keep) ++it; else it = cache_.erase(it);
    }
}

bool RoomKeyRegistry::has_secret() const {
    std::lock_guard<std::mutex> lk(mu_);
    return has_;
}

std::uint32_t RoomKeyRegistry::epoch() const {
    std::lock_guard<std::mutex> lk(mu_);
    return cur_epoch_;
}

std::optional<RoomKeyRegistry::SealKey> RoomKeyRegistry::seal_key() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (!has_) return std::nullopt;
    return cur_seal_;
}

std::optional<std::array<std::uint8_t, 32>> RoomKeyRegistry::open_key(
    std::string_view sender_pubkey, std::uint32_t frame_epoch) {
    std::lock_guard<std::mutex> lk(mu_);

    // Which secret covers this frame's epoch?
    const std::array<std::uint8_t, 32>* secret = nullptr;
    if (has_ && frame_epoch == cur_epoch_) {
        secret = &cur_secret_;
    } else if (has_prev_ && frame_epoch == prev_epoch_ && now() < prev_until_) {
        secret = &prev_secret_;   // still inside the rotation grace window
    }
    if (!secret) return std::nullopt;   // unknown / expired epoch → drop

    auto key = std::make_pair(std::string(sender_pubkey), frame_epoch);
    if (auto it = cache_.find(key); it != cache_.end()) return it->second;

    auto derived = derive_room_sframe_key(
        std::span<const std::uint8_t, 32>(secret->data(), 32),
        as_bytes(sender_pubkey), frame_epoch);
    cache_.emplace(std::move(key), derived);
    return derived;
}

}  // namespace fb::media
