// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/channel_gossip.hpp"

#include <stdexcept>

namespace fb::p2p {

std::string channel_topic_name(std::span<const std::uint8_t> channel_id) {
    if (channel_id.size() != 32) {
        throw std::invalid_argument(
            "channel_topic_name: channel_id must be exactly 32 bytes");
    }
    static const char hex[] = "0123456789abcdef";
    std::string out = kChannelGossipTopicPrefix;
    out.reserve(out.size() + 64);
    for (auto b : channel_id) {
        out.push_back(hex[(b >> 4) & 0x0f]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

}  // namespace fb::p2p
