// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/store/sqlite_store.hpp"

#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

// Per-test temp DB; removed in TearDown.
struct TmpDb : ::testing::Test {
    std::string path;
    void SetUp() override {
        char tmpl[] = "/tmp/fb_store_XXXXXX.db";
        const int fd = mkstemps(tmpl, 3);
        ASSERT_GE(fd, 0);
        ::close(fd);
        path = tmpl;
    }
    void TearDown() override {
        if (!path.empty()) ::unlink(path.c_str());
    }
};

std::vector<std::uint8_t> bytes(std::initializer_list<std::uint8_t> il) {
    return std::vector<std::uint8_t>(il);
}
std::span<const std::uint8_t> span_of(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

}  // namespace

TEST_F(TmpDb, OpenCreatesSchema) {
    auto s = fb::store::SqliteStore::open(path);
    EXPECT_NE(s, nullptr);
}

TEST_F(TmpDb, IdentityRoundTrip) {
    auto s = fb::store::SqliteStore::open(path);
    auto pub = bytes({1, 2, 3, 4});
    auto sec = bytes({0xff, 0xee, 0xdd});
    s->save_identity(span_of(pub), span_of(sec), "alice");
    auto got_pub = s->load_identity_pub("alice");
    auto got_sec = s->load_identity_sec("alice");
    ASSERT_TRUE(got_pub.has_value());
    EXPECT_EQ(*got_pub, pub);
    ASSERT_TRUE(got_sec.has_value());
    EXPECT_EQ(*got_sec, sec);
}

TEST_F(TmpDb, PeerCacheRoundTrip) {
    auto s = fb::store::SqliteStore::open(path);
    auto pk = bytes({0xa, 0xb, 0xc});
    s->remember_peer(span_of(pk), "bob");
    auto got = s->lookup_peer("bob");
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, pk);
}

TEST_F(TmpDb, SessionBlobRoundTrip) {
    auto s = fb::store::SqliteStore::open(path);
    auto peer = bytes({1, 2});
    auto blob = bytes({9, 8, 7, 6, 5});
    s->save_session(span_of(peer), span_of(blob));
    auto got = s->load_session(span_of(peer));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, blob);
}

TEST_F(TmpDb, InboxOrderingByTime) {
    auto s = fb::store::SqliteStore::open(path);
    auto peer = bytes({1});
    auto pt1 = bytes({'a'});
    auto pt2 = bytes({'b'});
    auto pt3 = bytes({'c'});
    auto e1 = bytes({1, 1, 1});
    auto e2 = bytes({2, 2, 2});
    auto e3 = bytes({3, 3, 3});
    s->append_inbox(span_of(e1), span_of(peer), span_of(pt1), 100);
    s->append_inbox(span_of(e2), span_of(peer), span_of(pt2), 200);
    s->append_inbox(span_of(e3), span_of(peer), span_of(pt3), 300);
    auto rows = s->recent_inbox(10);
    ASSERT_EQ(rows.size(), 3u);
    EXPECT_EQ(rows[0].timestamp_ms, 300u);
    EXPECT_EQ(rows[1].timestamp_ms, 200u);
    EXPECT_EQ(rows[2].timestamp_ms, 100u);
}

TEST_F(TmpDb, CarryLedgerAccumulates) {
    auto s = fb::store::SqliteStore::open(path);
    auto peer = bytes({4, 5, 6});
    EXPECT_EQ(s->carry_balance(span_of(peer)), 0);
    s->record_carry(span_of(peer), 100);
    s->record_carry(span_of(peer), 50);
    s->record_carry(span_of(peer), -30);
    EXPECT_EQ(s->carry_balance(span_of(peer)), 120);
}

TEST_F(TmpDb, ServerDirectoryRoundTripAndOverwrite) {
    auto s = fb::store::SqliteStore::open(path);
    auto pk1 = bytes({1, 2, 3});
    auto pk2 = bytes({9, 9, 9});
    EXPECT_FALSE(s->srv_resolve_username("alice").has_value());
    s->srv_register_user("alice", span_of(pk1));
    auto got = s->srv_resolve_username("alice");
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, pk1);
    s->srv_register_user("alice", span_of(pk2));   // overwrite
    EXPECT_EQ(*s->srv_resolve_username("alice"), pk2);
}

TEST_F(TmpDb, ServerPrekeyBundleRoundTrip) {
    auto s = fb::store::SqliteStore::open(path);
    auto pub = bytes({0xa, 0xb});
    auto bundle = bytes({1, 2, 3, 4});
    EXPECT_FALSE(s->srv_get_prekey_bundle(span_of(pub)).has_value());
    s->srv_put_prekey_bundle(span_of(pub), span_of(bundle));
    EXPECT_EQ(*s->srv_get_prekey_bundle(span_of(pub)), bundle);
}

TEST_F(TmpDb, ChannelStateAndPeers) {
    auto s = fb::store::SqliteStore::open(path);
    auto cid = bytes({0xa, 0xa});
    auto own = bytes({1});
    s->chan_save("general", span_of(cid), span_of(own));
    auto rows = s->chan_list();
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].name, "general");
    EXPECT_EQ(rows[0].channel_id, cid);
    EXPECT_EQ(rows[0].own_dist, own);

    auto peer = bytes({0xb});
    auto peer_dist = bytes({2, 3, 4});
    s->chan_save_peer(span_of(cid), span_of(peer), span_of(peer_dist));
    auto peers = s->chan_peers(span_of(cid));
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].peer_pub, peer);
    EXPECT_EQ(peers[0].peer_dist, peer_dist);
}

TEST_F(TmpDb, ChannelInboxOrdering) {
    auto s = fb::store::SqliteStore::open(path);
    auto cid = bytes({0xc});
    auto pub = bytes({0xd});
    s->chan_append_inbox(span_of(cid), span_of(pub), bytes({'a'}), 100);
    s->chan_append_inbox(span_of(cid), span_of(pub), bytes({'b'}), 200);
    auto rows = s->chan_recent_inbox(span_of(cid), 10);
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].timestamp_ms, 200u);
    EXPECT_EQ(rows[1].timestamp_ms, 100u);
}

TEST_F(TmpDb, PeerNameCache) {
    auto s = fb::store::SqliteStore::open(path);
    auto pub = bytes({1, 2, 3});
    EXPECT_FALSE(s->peer_name(span_of(pub)).has_value());
    s->cache_peer_name(span_of(pub), "alice");
    EXPECT_EQ(*s->peer_name(span_of(pub)), "alice");
    s->cache_peer_name(span_of(pub), "alicia");  // overwrite
    EXPECT_EQ(*s->peer_name(span_of(pub)), "alicia");
    auto all = s->all_cached_peers();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].username, "alicia");
}
