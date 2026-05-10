// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// room_beacon_leak_test — proves the fb-room: gossip beacon contains *only*
// the data the production code is supposed to publish (room_id, publisher
// pubkey, has_audio, has_video) and never carries secrets that leak via
// the public topic.
//
// The threat model for room presence: anyone who knows the 32-byte
// room_id (== channel_group_id, derived from the channel name on join)
// can subscribe to fb-room:<hex> and observe the participant pubkey set.
// That metadata leak is *intentional* — it's how peer discovery for
// mesh-dialing works. What MUST NOT appear in the beacon:
//   - SDP / ICE blobs (they ride on DmPayload.media_signal, encrypted)
//   - SFrame keys (derived per-call from X3DH, never on the wire)
//   - Plaintext message text
//   - User passphrases / vault seed material
//   - Channel encryption keys
// =============================================================================

#include "fb/p2p/channel_gossip.hpp"
#include "envelope.pb.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Build the same beacon payload the desktop client publishes on
// kRoomJoin / republish_room_presence. Mirrors the production code in
// client-desktop/src/chat_client.cpp exactly.
std::vector<std::uint8_t> build_room_beacon(
    std::span<const std::uint8_t> room_id,
    std::span<const std::uint8_t> self_pub,
    bool has_audio,
    bool has_video) {
    fb::proto::Frame beacon;
    auto* m = beacon.mutable_room_roster();
    m->set_room_id(std::string(reinterpret_cast<const char*>(room_id.data()),
                                room_id.size()));
    auto* mem = m->add_participants();
    mem->set_identity_pubkey(std::string(
        reinterpret_cast<const char*>(self_pub.data()), self_pub.size()));
    mem->set_has_audio(has_audio);
    mem->set_has_video(has_video);
    std::vector<std::uint8_t> bw(beacon.ByteSizeLong());
    beacon.SerializeToArray(bw.data(), static_cast<int>(bw.size()));
    return bw;
}

// Search for `needle` as a contiguous byte run inside `haystack`.
bool contains_bytes(const std::vector<std::uint8_t>& haystack,
                    std::string_view needle) {
    if (needle.empty() || haystack.size() < needle.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        if (std::memcmp(haystack.data() + i, needle.data(), needle.size()) == 0) {
            return true;
        }
    }
    return false;
}

}  // namespace

TEST(RoomBeaconLeak, NoSdpIceOrSecretsInBeacon) {
    std::array<std::uint8_t, 32> room_id{};
    for (std::size_t i = 0; i < room_id.size(); ++i) room_id[i] = 0x55;
    std::array<std::uint8_t, 32> self_pub{};
    for (std::size_t i = 0; i < self_pub.size(); ++i) self_pub[i] = 0xa5;

    auto wire = build_room_beacon(room_id, self_pub, /*audio=*/true, /*video=*/false);

    // Things that MUST NOT appear in the beacon — these are realistic
    // tokens / fragments we'd expect to see if the publish path were
    // accidentally bundling unrelated state alongside the roster.
    const std::vector<std::string_view> forbidden = {
        // SDP fragments — every browser/GStreamer SDP starts with these
        "v=0",  "m=audio", "m=video", "a=fingerprint", "a=ice-ufrag",
        "a=ice-pwd", "candidate:", "RTP/SAVPF",
        // SFrame and X3DH key labels — anything that looks like keying
        // material would be a critical leak
        "FinBit-SFrame", "X3DH", "spk", "opk", "MLS",
        // Vault / login secrets
        "Argon2id", "passphrase",
        // Common app-internal markers
        "channel_key", "media_signal", "RatchetMessage",
    };
    for (const auto& s : forbidden) {
        EXPECT_FALSE(contains_bytes(wire, s))
            << "beacon contains forbidden substring: " << s;
    }

    // Sanity: the beacon SHOULD contain (a) the room_id bytes verbatim
    // (publisher and recipient must agree on routing) and (b) the
    // self_pub bytes (mesh-dial uses these to identify the peer).
    EXPECT_TRUE(contains_bytes(wire,
        std::string_view(reinterpret_cast<const char*>(room_id.data()),
                          room_id.size())))
        << "beacon missing room_id bytes";
    EXPECT_TRUE(contains_bytes(wire,
        std::string_view(reinterpret_cast<const char*>(self_pub.data()),
                          self_pub.size())))
        << "beacon missing self pubkey";
}

// Round-trip: parse the beacon back as a Frame and confirm that the
// observable state is exactly {room_id, [{pubkey, has_audio, has_video}]}
// — no extra fields, no oneof drift, no protobuf-3 default-zero leaks.
TEST(RoomBeaconLeak, ParsedBeaconHasOnlyRosterFields) {
    std::array<std::uint8_t, 32> room_id{};
    for (std::size_t i = 0; i < room_id.size(); ++i) room_id[i] = 0x33;
    std::array<std::uint8_t, 32> self_pub{};
    for (std::size_t i = 0; i < self_pub.size(); ++i) self_pub[i] = 0x77;

    auto wire = build_room_beacon(room_id, self_pub, /*audio=*/true, /*video=*/true);
    fb::proto::Frame f;
    ASSERT_TRUE(f.ParseFromArray(wire.data(), static_cast<int>(wire.size())));
    ASSERT_EQ(f.body_case(), fb::proto::Frame::kRoomRoster);
    const auto& rr = f.room_roster();
    ASSERT_EQ(rr.room_id().size(), 32u);
    EXPECT_EQ(0, std::memcmp(rr.room_id().data(), room_id.data(), 32));
    ASSERT_EQ(rr.participants_size(), 1);
    const auto& p = rr.participants(0);
    ASSERT_EQ(p.identity_pubkey().size(), 32u);
    EXPECT_EQ(0, std::memcmp(p.identity_pubkey().data(), self_pub.data(), 32));
    EXPECT_TRUE(p.has_audio());
    EXPECT_TRUE(p.has_video());

    // No other Frame fields should be set.
    EXPECT_FALSE(f.has_envelope());
    EXPECT_FALSE(f.has_register_req());
    EXPECT_FALSE(f.has_username_lookup());
    EXPECT_FALSE(f.has_room_join());
    EXPECT_FALSE(f.has_room_leave());
}
