// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/kademlia.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

namespace {
fb::p2p::NodeId from_byte(std::uint8_t b) {
    fb::p2p::NodeId id{};
    for (auto& x : id) x = b;
    return id;
}
}  // namespace

TEST(KademliaPrimitives, XorDistanceIsCommutative) {
    fb::p2p::NodeId a = from_byte(0xAA);
    fb::p2p::NodeId b = from_byte(0x55);
    EXPECT_EQ(fb::p2p::xor_distance(a, b), fb::p2p::xor_distance(b, a));
}

TEST(KademliaPrimitives, BucketIndexZero) {
    fb::p2p::NodeId zero{};
    EXPECT_EQ(fb::p2p::bucket_index(zero), fb::p2p::kAddressBits);
}

TEST(KademliaPrimitives, BucketIndexHighestBit) {
    fb::p2p::NodeId d{};
    d[0] = 0x80;  // highest byte, highest bit
    EXPECT_EQ(fb::p2p::bucket_index(d), fb::p2p::kAddressBits - 1);
}

TEST(KademliaPrimitives, BucketIndexLowestBit) {
    fb::p2p::NodeId d{};
    d[fb::p2p::kNodeIdBytes - 1] = 0x01;
    EXPECT_EQ(fb::p2p::bucket_index(d), 0u);
}

TEST(RoutingTable, ObserveAndClosest) {
    fb::p2p::NodeId self{};
    fb::p2p::RoutingTable rt(self);
    for (std::uint8_t b = 1; b < 10; ++b) {
        fb::p2p::PeerInfo p;
        p.id = from_byte(b);
        p.addr = "127.0.0.1:" + std::to_string(8000 + b);
        EXPECT_TRUE(rt.observe(p));
    }
    EXPECT_EQ(rt.size(), 9u);
    auto closest = rt.closest(from_byte(0x01), 3);
    ASSERT_GE(closest.size(), 1u);
    EXPECT_EQ(closest.front().id, from_byte(0x01));
}

TEST(RoutingTable, IgnoresSelf) {
    fb::p2p::NodeId self{};
    fb::p2p::RoutingTable rt(self);
    fb::p2p::PeerInfo p;
    p.id = self;
    p.addr = "irrelevant";
    EXPECT_FALSE(rt.observe(p));
    EXPECT_EQ(rt.size(), 0u);
}

TEST(RoutingTable, NodeIdFromPubkeyDeterministic) {
    std::vector<std::uint8_t> pk1 = {1, 2, 3, 4, 5};
    std::vector<std::uint8_t> pk2 = {5, 4, 3, 2, 1};
    EXPECT_EQ(fb::p2p::node_id_from_pubkey(pk1), fb::p2p::node_id_from_pubkey(pk1));
    EXPECT_NE(fb::p2p::node_id_from_pubkey(pk1), fb::p2p::node_id_from_pubkey(pk2));
}
