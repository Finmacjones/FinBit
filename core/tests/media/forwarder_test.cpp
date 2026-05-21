// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/forwarder.hpp"

#include <gtest/gtest.h>

using fb::media::ForwarderCandidate;
using fb::media::elect_forwarder;
using fb::media::plan_topology;

namespace {
std::vector<ForwarderCandidate> cands(
    std::initializer_list<std::pair<std::string, int>> il) {
    std::vector<ForwarderCandidate> v;
    for (auto& [k, c] : il) v.push_back({k, c});
    return v;
}
constexpr std::size_t kMesh = 6;
}  // namespace

TEST(ForwarderElect, SmallRoomStaysMesh) {
    // 5 participants (< threshold 6) → mesh, even with strong candidates.
    EXPECT_EQ(elect_forwarder(cands({{"a", 3}, {"b", 2}, {"c", 1},
                                     {"d", 1}, {"e", 1}}), kMesh),
              "");
}

TEST(ForwarderElect, HighestUplinkClassWins) {
    auto c = cands({{"a", 1}, {"b", 3}, {"c", 2}, {"d", 1}, {"e", 1}, {"f", 1}});
    EXPECT_EQ(elect_forwarder(c, kMesh), "b");  // class 3 (volunteer)
}

TEST(ForwarderElect, TieBrokenByLowestPubkey) {
    // Two class-2 candidates → deterministic: smallest pubkey.
    auto c = cands({{"z", 2}, {"a", 2}, {"m", 1}, {"n", 1}, {"o", 1}, {"p", 1}});
    EXPECT_EQ(elect_forwarder(c, kMesh), "a");
}

TEST(ForwarderElect, NoCapableCandidateStaysMesh) {
    // Big room but everyone is leaf-only (class 0) → mesh fallback.
    auto c = cands({{"a", 0}, {"b", 0}, {"c", 0}, {"d", 0}, {"e", 0}, {"f", 0}});
    EXPECT_EQ(elect_forwarder(c, kMesh), "");
}

TEST(ForwarderElect, DeterministicAcrossOrderings) {
    // Same set, different vector order → same forwarder (every peer agrees).
    auto c1 = cands({{"a", 1}, {"b", 2}, {"c", 2}, {"d", 1}, {"e", 1}, {"f", 1}});
    auto c2 = cands({{"f", 1}, {"e", 1}, {"d", 1}, {"c", 2}, {"b", 2}, {"a", 1}});
    EXPECT_EQ(elect_forwarder(c1, kMesh), elect_forwarder(c2, kMesh));
    EXPECT_EQ(elect_forwarder(c1, kMesh), "b");  // tie b/c → smaller "b"
}

TEST(ForwarderPlan, MeshDialsAllOthers) {
    auto p = plan_topology({"me", "x", "y"}, "me", /*forwarder=*/"");
    EXPECT_TRUE(p.mesh);
    EXPECT_FALSE(p.i_am_forwarder);
    EXPECT_EQ(p.dial, (std::vector<std::string>{"x", "y"}));
}

TEST(ForwarderPlan, ForwarderConnectsToEveryone) {
    auto p = plan_topology({"me", "x", "y", "z"}, "me", /*forwarder=*/"me");
    EXPECT_FALSE(p.mesh);
    EXPECT_TRUE(p.i_am_forwarder);
    EXPECT_EQ(p.dial, (std::vector<std::string>{"x", "y", "z"}));
}

TEST(ForwarderPlan, LeafConnectsOnlyToForwarder) {
    auto p = plan_topology({"me", "x", "y", "fwd"}, "me", /*forwarder=*/"fwd");
    EXPECT_FALSE(p.mesh);
    EXPECT_FALSE(p.i_am_forwarder);
    EXPECT_EQ(p.dial, (std::vector<std::string>{"fwd"}));
}
