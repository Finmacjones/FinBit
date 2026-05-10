// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/channel_gossip.hpp"

#include <stdexcept>

namespace fb::p2p {

namespace {
std::string hex_topic(std::string_view prefix,
                      std::span<const std::uint8_t> id) {
    static const char hex[] = "0123456789abcdef";
    std::string out(prefix);
    out.reserve(out.size() + 64);
    for (auto b : id) {
        out.push_back(hex[(b >> 4) & 0x0f]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}
}  // namespace

std::string channel_topic_name(std::span<const std::uint8_t> channel_id) {
    if (channel_id.size() != 32) {
        throw std::invalid_argument(
            "channel_topic_name: channel_id must be exactly 32 bytes");
    }
    return hex_topic(kChannelGossipTopicPrefix, channel_id);
}

std::string room_topic_name(std::span<const std::uint8_t> room_id) {
    if (room_id.size() != 32) {
        throw std::invalid_argument(
            "room_topic_name: room_id must be exactly 32 bytes");
    }
    return hex_topic(kRoomGossipTopicPrefix, room_id);
}

}  // namespace fb::p2p
