// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/track_bindings.hpp"

#include <string>

#include "envelope.pb.h"

namespace fb::media {

void bind_track(fb::proto::RoomOffer& offer, std::string_view mid,
                std::span<const std::uint8_t> sender_pubkey) {
    auto* tb = offer.add_track_bindings();
    tb->set_mid(std::string(mid));
    tb->set_sender_pubkey(sender_pubkey.data(), sender_pubkey.size());
}

std::optional<std::vector<std::uint8_t>> sender_for_track(
    const fb::proto::RoomOffer& offer, std::string_view mid) {
    if (mid.empty()) return std::nullopt;
    for (const auto& tb : offer.track_bindings()) {
        if (tb.mid() == mid) {
            const auto& pk = tb.sender_pubkey();
            return std::vector<std::uint8_t>(pk.begin(), pk.end());
        }
    }
    return std::nullopt;
}

}  // namespace fb::media
