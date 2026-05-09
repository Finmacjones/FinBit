// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// channel_gossip — naming convention + helpers for routing FinBit channel
// envelopes over the existing fb::p2p::P2PNode gossipsub primitives.
//
// FinBit's centralized mode fans out channel envelopes via the server's
// `chan_subscribe` / per-subscriber broadcast machinery. In serverless
// mode, each channel becomes a gossipsub topic; channel members subscribe
// to the topic and publishes flood through the gossip mesh until every
// subscriber sees the envelope.
//
// This file is intentionally thin: it just pins the (channel_id → topic
// name) function so every peer agrees on the topic string for a given
// 32-byte channel id. The actual subscribe/publish/recv work is done
// directly on P2PNode — there's no separate ChannelGossip class.
//
// Naming convention: "fb-chan:" + lowercase-hex(channel_id). Stable
// across versions; future bump goes through a v2 prefix.
//
// Wire payload: serialized fb::proto::Envelope (the same wire shape the
// centralized server fans out as Frame.envelope). Receivers parse the
// payload and route through the existing channel-decrypt path. No
// transformation needed at the gossip layer — the Envelope is already
// AEAD-encrypted at the SenderKeys / MLS layer above.
// =============================================================================

#include <cstdint>
#include <span>
#include <string>

namespace fb::p2p {

constexpr const char* kChannelGossipTopicPrefix = "fb-chan:";

// 32B channel_id → "fb-chan:<lowercase-hex-64-chars>".
[[nodiscard]] std::string channel_topic_name(
    std::span<const std::uint8_t> channel_id);

}  // namespace fb::p2p
