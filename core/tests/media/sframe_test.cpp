// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/sframe.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {
std::array<std::uint8_t, 32> demo_base_key() {
    std::array<std::uint8_t, 32> k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(0xA0 ^ i);
    return k;
}
std::vector<std::uint8_t> bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
}  // namespace

TEST(SFrame, RoundTripSucceeds) {
    auto k = demo_base_key();
    auto pt = bytes("a frame of audio or video");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 42,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto recovered = fb::media::sframe_open_v1(
        std::span<const std::uint8_t, 32>(k),
        std::span<const std::uint8_t>(sealed.data(), sealed.size()));
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(*recovered, pt);
}

TEST(SFrame, DifferentCountersProduceDifferentCiphertext) {
    auto k = demo_base_key();
    auto pt = bytes("same plaintext");
    auto a = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 1,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto b = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 2,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_NE(a, b);
}

TEST(SFrame, DifferentEpochsProduceDifferentCiphertext) {
    auto k = demo_base_key();
    auto pt = bytes("same plaintext");
    auto a = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 99,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto b = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 2, 99,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_NE(a, b);
}

TEST(SFrame, WrongKeyFailsOpen) {
    auto k1 = demo_base_key();
    std::array<std::uint8_t, 32> k2{};
    for (std::size_t i = 0; i < k2.size(); ++i) k2[i] = 0x77;
    auto pt = bytes("oof");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k1), 0, 0,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(k2),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

TEST(SFrame, TamperedHeaderRejected) {
    auto k = demo_base_key();
    auto pt = bytes("payload");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 5,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    sealed[0] ^= 0x01;  // flip a header bit (epoch high byte)
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(k),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

TEST(SFrame, TamperedCiphertextRejected) {
    auto k = demo_base_key();
    auto pt = bytes("payload");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 5,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    sealed.back() ^= 0x01;
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(k),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

TEST(SFrame, DeterministicSealForSameInputs) {
    auto k = demo_base_key();
    auto pt = bytes("same input -> same output");
    auto a = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 7, 12345,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto b = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 7, 12345,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_EQ(a, b) << "SFrame seal must be deterministic for fixed (key, epoch, counter)";
}

// ---------------------------------------------------------------------------
// Group (forwarded-room) keying — derive_room_sframe_key (Lever B).
// ---------------------------------------------------------------------------
namespace {
std::array<std::uint8_t, 32> demo_room_secret(std::uint8_t seed = 0x11) {
    std::array<std::uint8_t, 32> s{};
    for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(seed + i);
    return s;
}
std::vector<std::uint8_t> pub(std::uint8_t tag) {
    return std::vector<std::uint8_t>(32, tag);  // a 32-byte "pubkey"
}
std::array<std::uint8_t, 32> room_key(const std::array<std::uint8_t, 32>& secret,
                                      const std::vector<std::uint8_t>& sender,
                                      std::uint32_t epoch) {
    return fb::media::derive_room_sframe_key(
        std::span<const std::uint8_t, 32>(secret),
        std::span<const std::uint8_t>(sender.data(), sender.size()), epoch);
}
}  // namespace

TEST(SFrameRoomKey, DeterministicForSameInputs) {
    auto s = demo_room_secret();
    EXPECT_EQ(room_key(s, pub(0xAA), 1), room_key(s, pub(0xAA), 1));
}

TEST(SFrameRoomKey, DistinctPerSender) {
    auto s = demo_room_secret();
    EXPECT_NE(room_key(s, pub(0xAA), 1), room_key(s, pub(0xBB), 1));
}

TEST(SFrameRoomKey, DistinctPerEpoch) {
    auto s = demo_room_secret();
    EXPECT_NE(room_key(s, pub(0xAA), 1), room_key(s, pub(0xAA), 2));
}

TEST(SFrameRoomKey, DistinctPerRoomSecret) {
    EXPECT_NE(room_key(demo_room_secret(0x11), pub(0xAA), 1),
              room_key(demo_room_secret(0x22), pub(0xAA), 1));
}

// The derived per-sender key is a usable SFrame base_key: a frame sealed
// with sender A's key opens with A's key (any room member can derive it).
TEST(SFrameRoomKey, DerivedKeySealsAndOpens) {
    auto s = demo_room_secret();
    auto kA = room_key(s, pub(0xAA), 3);
    auto pt = bytes("hello from sender A");
    auto sealed = fb::media::sframe_seal_v1(
        std::span<const std::uint8_t, 32>(kA), 3, 0,
        std::span<const std::uint8_t>(pt.data(), pt.size()));
    // A different member re-derives A's key from the shared room_secret.
    auto kA_again = room_key(s, pub(0xAA), 3);
    auto opened = fb::media::sframe_open_v1(
        std::span<const std::uint8_t, 32>(kA_again),
        std::span<const std::uint8_t>(sealed.data(), sealed.size()));
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(*opened, pt);
}

// Cross-sender isolation: a frame sealed with A's key does NOT open with
// B's key, even though both come from the same room_secret.
TEST(SFrameRoomKey, CrossSenderKeyDoesNotOpen) {
    auto s = demo_room_secret();
    auto kA = room_key(s, pub(0xAA), 3);
    auto kB = room_key(s, pub(0xBB), 3);
    auto pt = bytes("only A's receivers... well, everyone, but with A's key");
    auto sealed = fb::media::sframe_seal_v1(
        std::span<const std::uint8_t, 32>(kA), 3, 0,
        std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(kB),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

// sframe_peek_epoch reads the wire epoch WITHOUT opening the frame — the
// forwarded-room receiver uses it to pick the per-sender/epoch key first.
TEST(SFramePeekEpoch, MatchesSealedEpoch) {
    auto s = demo_room_secret();
    auto pt = bytes("pick the right key before opening");
    for (std::uint32_t epoch : {0u, 1u, 9u, 4242u}) {
        auto k = room_key(s, pub(0xAA), epoch);
        auto sealed = fb::media::sframe_seal_v1(
            std::span<const std::uint8_t, 32>(k), epoch, 7,
            std::span<const std::uint8_t>(pt.data(), pt.size()));
        auto peeked = fb::media::sframe_peek_epoch(
            std::span<const std::uint8_t>(sealed.data(), sealed.size()));
        ASSERT_TRUE(peeked.has_value());
        EXPECT_EQ(*peeked, epoch);
    }
}

TEST(SFramePeekEpoch, ShortFrameReturnsNullopt) {
    std::vector<std::uint8_t> too_short(11, 0xff);   // header is 12 bytes
    EXPECT_FALSE(fb::media::sframe_peek_epoch(
                     std::span<const std::uint8_t>(too_short.data(), too_short.size()))
                     .has_value());
    std::vector<std::uint8_t> empty;
    EXPECT_FALSE(fb::media::sframe_peek_epoch(
                     std::span<const std::uint8_t>(empty.data(), empty.size()))
                     .has_value());
}
