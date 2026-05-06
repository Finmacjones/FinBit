// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Domain model — passive value types used by the rest of the codebase.
// No persistence, no encryption, no networking concerns here. The MLS group
// state and message bodies are stored separately (see crypto/mls_facade and
// store/sqlite_store).

#include <array>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace fb::model {

using IdBytes = std::array<std::uint8_t, 32>;

struct User {
    IdBytes     identity_pubkey{};
    std::string username;
    std::string display_name;
    std::uint64_t last_seen_ms = 0;
};

struct Channel {
    IdBytes     channel_id{};   // MLS group_id
    std::string name;
    std::string topic;
    bool        is_voice = false;
    std::unordered_set<std::string> bridged_mesh_topics;  // populated for mesh-bridged channels
};

struct Server {  // Discord-style "guild"
    IdBytes     server_id{};
    std::string name;
    std::vector<Channel> channels;
    std::vector<IdBytes> members;
};

struct Message {
    std::array<std::uint8_t, 16> envelope_id{};
    IdBytes                      sender_pubkey{};
    IdBytes                      channel_id{};   // zero-filled for DMs
    IdBytes                      dm_peer_pubkey{};  // zero-filled for channel msgs
    std::uint64_t                timestamp_ms = 0;
    std::vector<std::uint8_t>    plaintext;
};

}  // namespace fb::model
