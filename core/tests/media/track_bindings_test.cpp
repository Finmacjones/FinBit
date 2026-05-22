// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/track_bindings.hpp"

#include <gtest/gtest.h>

#include <vector>

#include "envelope.pb.h"

using fb::media::bind_track;
using fb::media::sender_for_track;

namespace {
std::vector<std::uint8_t> pk(std::uint8_t fill) {
    return std::vector<std::uint8_t>(32, fill);
}
}  // namespace

TEST(TrackBindings, BindAndLookupRoundTrip) {
    fb::proto::RoomOffer offer;
    auto a = pk(0xa1), b = pk(0xb2);
    bind_track(offer, "0", std::span<const std::uint8_t>(a.data(), a.size()));
    bind_track(offer, "1", std::span<const std::uint8_t>(b.data(), b.size()));

    ASSERT_EQ(offer.track_bindings_size(), 2);
    EXPECT_EQ(sender_for_track(offer, "0"), a);
    EXPECT_EQ(sender_for_track(offer, "1"), b);
}

TEST(TrackBindings, MissingMidReturnsNullopt) {
    fb::proto::RoomOffer offer;
    auto a = pk(0xa1);
    bind_track(offer, "0", std::span<const std::uint8_t>(a.data(), a.size()));
    EXPECT_FALSE(sender_for_track(offer, "9").has_value());
}

TEST(TrackBindings, EmptyMidNeverMatches) {
    fb::proto::RoomOffer offer;
    auto a = pk(0xa1);
    // Even a (malformed) empty-mid binding must not be returned for an
    // empty query — empty mid is treated as "no binding".
    bind_track(offer, "", std::span<const std::uint8_t>(a.data(), a.size()));
    EXPECT_FALSE(sender_for_track(offer, "").has_value());
}

TEST(TrackBindings, FirstMatchWinsDeterministically) {
    fb::proto::RoomOffer offer;
    auto a = pk(0xa1), b = pk(0xb2);
    bind_track(offer, "0", std::span<const std::uint8_t>(a.data(), a.size()));
    bind_track(offer, "0", std::span<const std::uint8_t>(b.data(), b.size()));
    EXPECT_EQ(sender_for_track(offer, "0"), a);   // first wins
}

TEST(TrackBindings, EmptyOfferHasNoBindings) {
    fb::proto::RoomOffer offer;
    EXPECT_EQ(offer.track_bindings_size(), 0);
    EXPECT_FALSE(sender_for_track(offer, "0").has_value());
}
