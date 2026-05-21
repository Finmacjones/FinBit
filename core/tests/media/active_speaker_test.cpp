// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/active_speaker.hpp"

#include <gtest/gtest.h>

using fb::media::select_active_speakers;

namespace {
constexpr double kFloor = -50.0;
constexpr std::size_t kK = 8;
}  // namespace

TEST(ActiveSpeaker, GatesNobodyWhenWithinCapacity) {
    // 3 talking, 2 silent, cap 8 → everyone audible (no gating).
    std::map<std::string, double> levels{
        {"a", -10.0}, {"b", -20.0}, {"c", -15.0},
        {"d", -120.0}, {"e", -90.0}};
    auto audible = select_active_speakers(levels, kK, kFloor);
    EXPECT_EQ(audible.size(), 5u);
    for (const auto& k : {"a", "b", "c", "d", "e"}) EXPECT_TRUE(audible.count(k));
}

TEST(ActiveSpeaker, KeepsLoudestKWhenOverCapacity) {
    // 10 talkers, cap 3 → keep the 3 loudest, gate the rest.
    std::map<std::string, double> levels;
    for (int i = 0; i < 10; ++i) {
        levels[std::string("p") + char('0' + i)] = -10.0 - i;  // p0 loudest
    }
    auto audible = select_active_speakers(levels, 3, kFloor);
    ASSERT_EQ(audible.size(), 3u);
    EXPECT_TRUE(audible.count("p0"));
    EXPECT_TRUE(audible.count("p1"));
    EXPECT_TRUE(audible.count("p2"));
    EXPECT_FALSE(audible.count("p3"));
    EXPECT_FALSE(audible.count("p9"));
}

TEST(ActiveSpeaker, SilentPeersDoNotCountTowardCapacity) {
    // 2 talkers + 20 silent, cap 3 → 2 talkers <= cap → gate nobody.
    std::map<std::string, double> levels{{"loud1", -8.0}, {"loud2", -9.0}};
    for (int i = 0; i < 20; ++i) levels[std::string("s") + char('a' + i)] = -110.0;
    auto audible = select_active_speakers(levels, 3, kFloor);
    EXPECT_EQ(audible.size(), 22u);  // everyone audible
}

TEST(ActiveSpeaker, EmptyRoom) {
    EXPECT_TRUE(select_active_speakers({}, kK, kFloor).empty());
}

TEST(ActiveSpeaker, TieBreakIsDeterministic) {
    // Equal levels, cap 2 → lowest two keys win (stable order).
    std::map<std::string, double> levels{
        {"z", -10.0}, {"a", -10.0}, {"m", -10.0}};
    auto audible = select_active_speakers(levels, 2, kFloor);
    ASSERT_EQ(audible.size(), 2u);
    EXPECT_TRUE(audible.count("a"));
    EXPECT_TRUE(audible.count("m"));
    EXPECT_FALSE(audible.count("z"));
}
