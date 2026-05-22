// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Track→sender binding helpers for forwarded group calls (Lever B;
// docs/gstreamer-relay-spec.md §6A.3).
//
// In a forwarded room the SFU-shaped peer relays each member's sealed media on
// its own SDP media section. A subscriber must know WHICH member a given
// inbound track carries so it can open it with that sender's per-room SFrame
// key (RoomKeyRegistry::open_key). The forwarder publishes that map as
// RoomOffer.track_bindings (mid → sender_pubkey) — identity metadata it fills
// in from the room roster while holding no key, so it stays E2E blind.
//
// These are the pure builder/lookup helpers around that field; the GStreamer
// wiring that consumes them (read the inbound pad's mid, look up the sender,
// build an SframeOpenCtx) is the hardware-gated piece.
// =============================================================================

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace fb::proto {
class RoomOffer;
}

namespace fb::media {

// Forwarder side: record that the media section `mid` in this offer carries
// `sender_pubkey`'s stream. Appends one TrackBinding.
void bind_track(fb::proto::RoomOffer& offer, std::string_view mid,
                std::span<const std::uint8_t> sender_pubkey);

// Subscriber side: which member does `mid` carry? Returns the 32-byte sender
// pubkey, or std::nullopt if no binding matches (the first match wins; a
// well-formed offer has at most one per mid). An empty `mid` never matches.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> sender_for_track(
    const fb::proto::RoomOffer& offer, std::string_view mid);

}  // namespace fb::media
