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

// ---------------------------------------------------------------------------
// Lever C — plan_forwarded_video
// ---------------------------------------------------------------------------
using fb::media::VideoQuality;
using fb::media::plan_forwarded_video;

namespace {
constexpr double kFloor = -50.0;
}

TEST(ForwardedVideo, TopTalkersHighRestThumbnailThenDrop) {
    // 5 talkers (loud→quiet a..e) + 1 silent (z). max_high=2, max_thumb=2.
    std::map<std::string, double> levels{
        {"a", -5}, {"b", -10}, {"c", -15}, {"d", -20}, {"e", -25}, {"z", -120}};
    auto p = plan_forwarded_video(levels, /*max_high=*/2, /*max_thumb=*/2, kFloor);
    EXPECT_EQ(p["a"], VideoQuality::kHigh);
    EXPECT_EQ(p["b"], VideoQuality::kHigh);
    EXPECT_EQ(p["c"], VideoQuality::kThumbnail);
    EXPECT_EQ(p["d"], VideoQuality::kThumbnail);
    EXPECT_EQ(p["e"], VideoQuality::kDrop);
    EXPECT_EQ(p["z"], VideoQuality::kDrop);
}

TEST(ForwardedVideo, SmallRoomEveryoneVisible) {
    // 2 talkers, generous budget → both HIGH, none dropped.
    std::map<std::string, double> levels{{"a", -8}, {"b", -9}};
    auto p = plan_forwarded_video(levels, 4, 8, kFloor);
    EXPECT_EQ(p["a"], VideoQuality::kHigh);
    EXPECT_EQ(p["b"], VideoQuality::kHigh);
}

TEST(ForwardedVideo, DeterministicTieBreak) {
    std::map<std::string, double> levels{{"z", -10}, {"a", -10}, {"m", -10}};
    auto p = plan_forwarded_video(levels, 1, 1, kFloor);
    EXPECT_EQ(p["a"], VideoQuality::kHigh);       // lowest key wins HIGH
    EXPECT_EQ(p["m"], VideoQuality::kThumbnail);
    EXPECT_EQ(p["z"], VideoQuality::kDrop);
}

// ---------------------------------------------------------------------------
// Lever D — build_distribution_tree
// ---------------------------------------------------------------------------
using fb::media::TreeNode;
using fb::media::build_distribution_tree;

namespace {
std::vector<ForwarderCandidate> cap(std::initializer_list<std::pair<std::string,int>> il) {
    std::vector<ForwarderCandidate> v;
    for (auto& [k, c] : il) v.push_back({k, c});
    return v;
}
const TreeNode* find(const std::vector<TreeNode>& t, const std::string& k) {
    for (const auto& n : t) if (n.pubkey == k) return &n;
    return nullptr;
}
}

TEST(DistTree, EmptyAndSingle) {
    EXPECT_TRUE(build_distribution_tree({}, 3).empty());
    auto one = build_distribution_tree(cap({{"a", 1}}), 3);
    ASSERT_EQ(one.size(), 1u);
    EXPECT_EQ(one[0].parent, "");
    EXPECT_EQ(one[0].depth, 0);
}

TEST(DistTree, RootIsStrongestRespectsFanoutBoundsDepth) {
    // 7 nodes, fanout 2. Strongest (class 3 = "s") is root; depth ≤ 2.
    auto t = build_distribution_tree(
        cap({{"a",1},{"b",1},{"c",1},{"d",1},{"e",1},{"f",1},{"s",3}}), 2);
    ASSERT_EQ(t.size(), 7u);
    EXPECT_EQ(t[0].pubkey, "s");
    EXPECT_EQ(t[0].parent, "");
    // Every non-root has a parent that appears in the tree; depth = parent+1.
    int max_depth = 0;
    std::map<std::string,int> child_count;
    for (const auto& n : t) {
        if (n.parent.empty()) { EXPECT_EQ(n.depth, 0); continue; }
        const TreeNode* par = find(t, n.parent);
        ASSERT_NE(par, nullptr);
        EXPECT_EQ(n.depth, par->depth + 1);
        child_count[n.parent]++;
        max_depth = std::max(max_depth, n.depth);
    }
    for (const auto& [_, c] : child_count) EXPECT_LE(c, 2);  // fanout respected
    EXPECT_LE(max_depth, 2);                                  // shallow
}

TEST(DistTree, DeterministicAcrossOrderings) {
    auto t1 = build_distribution_tree(cap({{"a",1},{"b",2},{"c",1},{"d",1}}), 2);
    auto t2 = build_distribution_tree(cap({{"d",1},{"c",1},{"b",2},{"a",1}}), 2);
    ASSERT_EQ(t1.size(), t2.size());
    for (std::size_t i = 0; i < t1.size(); ++i) {
        EXPECT_EQ(t1[i].pubkey, t2[i].pubkey);
        EXPECT_EQ(t1[i].parent, t2[i].parent);
    }
    EXPECT_EQ(t1[0].pubkey, "b");   // class 2 → root
}
