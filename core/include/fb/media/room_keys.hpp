// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// RoomKeyRegistry — room-scoped SFrame key store for forwarded group calls
// (Lever B; docs/serverless-group-calls.md, gstreamer-relay-spec.md §6A).
//
// A forwarded room shares a 32-byte room_secret (sourced from the MLS
// exporter — MlsGroup::export_room_secret — or a distributed RoomKey for
// SenderKeys channels; both shipped). From it every member derives, via
// fb::media::derive_room_sframe_key:
//
//   K_self   = derive(secret, my_pubkey,     epoch)   → seal own frames
//   K_sender = derive(secret, sender_pubkey,  epoch)   → open that sender's
//
// This registry owns the current room_secret + epoch, caches those
// derivations, and keeps the PREVIOUS epoch's secret alive for a short grace
// window so frames still in flight when membership changes (a rekey) keep
// opening. The frame's own header carries the epoch (sframe_peek_epoch), so
// the receiver picks the matching key unambiguously across a rotation.
//
// This is the pure half of the per-sender open-key plumbing: the GStreamer
// pad probes (the hardware-gated piece) consume a RoomKeyRegistry; the
// registry itself is deterministic and unit-tested. It is intentionally
// roster-agnostic — it derives a key for whatever sender pubkey it's asked
// about; a forged/non-member sender simply yields a key that won't open real
// frames (the AEAD tag check downstream rejects them).
//
// Thread-safe: the open probe calls open_key() on GStreamer streaming threads
// while the control thread calls set_secret() on a rekey.
// =============================================================================

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace fb::media {

class RoomKeyRegistry {
public:
    // Injectable monotonic clock (tests drive the grace window deterministically;
    // production leaves it default → std::chrono::steady_clock::now).
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    struct SealKey {
        std::array<std::uint8_t, 32> key{};
        std::uint32_t                epoch = 0;
    };

    // `my_pubkey` is this member's 32-byte identity (the seal identity).
    // `grace` is how long a superseded epoch's keys keep opening after a
    // rotation (default 3 s). `clock` is for tests; empty → steady_clock.
    explicit RoomKeyRegistry(
        std::array<std::uint8_t, 32> my_pubkey,
        std::chrono::milliseconds grace = std::chrono::seconds(3),
        Clock clock = {});

    // Install / rotate the room secret. Call when room_secrets[room_id]
    // changes (MLS commit / RoomKey rotation). A strictly-higher epoch shifts
    // the current secret into the grace slot and recomputes K_self. A repeat
    // of (or anything ≤) the current epoch is ignored — stale or duplicate.
    void set_secret(std::span<const std::uint8_t, 32> secret, std::uint32_t epoch);

    [[nodiscard]] bool          has_secret() const;
    [[nodiscard]] std::uint32_t epoch() const;   // current epoch, 0 if none

    // K_self at the current epoch (precomputed on set_secret). nullopt before
    // any secret is installed.
    [[nodiscard]] std::optional<SealKey> seal_key() const;

    // K_sender for `sender_pubkey` (raw identity bytes) at the epoch carried
    // in the frame (see sframe_peek_epoch). Accepts the current epoch, or the
    // previous epoch while still inside the grace window; anything else →
    // nullopt (caller drops the frame). Derives on first use, caches by
    // (sender, epoch).
    [[nodiscard]] std::optional<std::array<std::uint8_t, 32>> open_key(
        std::string_view sender_pubkey, std::uint32_t frame_epoch);

private:
    [[nodiscard]] std::chrono::steady_clock::time_point now() const;

    mutable std::mutex          mu_;
    std::array<std::uint8_t, 32> my_pubkey_{};
    std::chrono::milliseconds   grace_;
    Clock                       clock_;

    bool                         has_       = false;
    std::array<std::uint8_t, 32> cur_secret_{};
    std::uint32_t                cur_epoch_ = 0;
    SealKey                      cur_seal_{};

    bool                         has_prev_   = false;
    std::array<std::uint8_t, 32> prev_secret_{};
    std::uint32_t                prev_epoch_ = 0;
    std::chrono::steady_clock::time_point prev_until_{};

    // (sender_pubkey bytes, epoch) → derived K_sender.
    std::map<std::pair<std::string, std::uint32_t>,
             std::array<std::uint8_t, 32>> cache_;
};

}  // namespace fb::media
