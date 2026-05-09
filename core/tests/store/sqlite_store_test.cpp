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
    // Default crypto is SenderKeys when not specified explicitly.
    EXPECT_EQ(rows[0].crypto, fb::store::SqliteStore::ChannelCrypto::kSenderKeys);

    auto peer = bytes({0xb});
    auto peer_dist = bytes({2, 3, 4});
    s->chan_save_peer(span_of(cid), span_of(peer), span_of(peer_dist));
    auto peers = s->chan_peers(span_of(cid));
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].peer_pub, peer);
    EXPECT_EQ(peers[0].peer_dist, peer_dist);
}

// Per-channel crypto column round-trips. New MLS channels read back
// as kMls; legacy SenderKeys stays the default; the column survives a
// reopen (single-process re-open the same path).
TEST_F(TmpDb, ChannelCryptoRoundTripsAcrossReopen) {
    auto cid_mls = bytes({0x01, 0x02});
    auto cid_sk  = bytes({0x03, 0x04});
    auto own = bytes({1, 2, 3});
    {
        auto s = fb::store::SqliteStore::open(path);
        s->chan_save("mls-room", span_of(cid_mls), span_of(own),
                     fb::store::SqliteStore::ChannelCrypto::kMls);
        s->chan_save("sk-room", span_of(cid_sk), span_of(own),
                     fb::store::SqliteStore::ChannelCrypto::kSenderKeys);
    }
    auto s = fb::store::SqliteStore::open(path);
    auto rows = s->chan_list();
    ASSERT_EQ(rows.size(), 2u);
    auto by_name = [&](const std::string& nm) {
        for (const auto& r : rows) if (r.name == nm) return r;
        ADD_FAILURE() << "no row for " << nm;
        return fb::store::SqliteStore::ChannelRow{};
    };
    EXPECT_EQ(by_name("mls-room").crypto,
              fb::store::SqliteStore::ChannelCrypto::kMls);
    EXPECT_EQ(by_name("sk-room").crypto,
              fb::store::SqliteStore::ChannelCrypto::kSenderKeys);
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

// At-rest AEAD: opening with a master_key wraps inbox/outbox plaintext
// columns; decryption is automatic on the read path; the canary
// plaintext does NOT appear anywhere in the .db file once written.
TEST_F(TmpDb, AtRestEncryptionRoundTrip) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) {
        master_key[i] = static_cast<std::uint8_t>(i + 1);
    }
    const std::string canary = "ATREST_CANARY_NEEDLE_XYZZY";
    auto envid = bytes({0x10, 0x11, 0x12, 0x13});
    auto peer  = bytes({0x20, 0x21, 0x22, 0x23});
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        std::vector<std::uint8_t> pt(canary.begin(), canary.end());
        s->append_inbox(span_of(envid), span_of(peer), span_of(pt), 12345);
        s->append_outbox(span_of(envid), span_of(peer), span_of(pt), 12345);
    }
    // Re-open under the same key; decryption surfaces the canary.
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        auto rows = s->recent_inbox(10);
        ASSERT_EQ(rows.size(), 1u);
        std::string got(rows[0].plaintext.begin(), rows[0].plaintext.end());
        EXPECT_EQ(got, canary);
        auto out_rows = s->recent_outbox(10);
        ASSERT_EQ(out_rows.size(), 1u);
        std::string got_out(out_rows[0].plaintext.begin(), out_rows[0].plaintext.end());
        EXPECT_EQ(got_out, canary);
    }
    // The canary must NOT appear in the raw on-disk bytes.
    FILE* f = std::fopen(path.c_str(), "rb");
    ASSERT_NE(f, nullptr);
    std::fseek(f, 0, SEEK_END);
    const long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<char> file(static_cast<std::size_t>(sz));
    ASSERT_EQ(std::fread(file.data(), 1, file.size(), f), file.size());
    std::fclose(f);
    const auto needle = std::string_view(canary);
    EXPECT_EQ(std::string_view(file.data(), file.size()).find(needle),
              std::string_view::npos)
        << "canary plaintext leaked through to the SQLite file — at-rest "
           "encryption is not active";
    // Re-opening under a WRONG key drops rows on read (returns empty).
    std::array<std::uint8_t, 32> wrong_key{};
    for (auto& b : wrong_key) b = 0xff;
    auto s = fb::store::SqliteStore::open(path,
        std::span<const std::uint8_t>(wrong_key.data(), wrong_key.size()));
    EXPECT_TRUE(s->recent_inbox(10).empty());
    EXPECT_TRUE(s->recent_outbox(10).empty());
}

// At-rest AEAD also covers sessions, channels, and the peer-name
// cache (the rest of the on-disk surface). Each test writes through
// the high-level API, then greps the raw .db file for the canary
// — must be absent. Reopens under the same key surface the canary
// through the read path.
TEST_F(TmpDb, AtRestEncryptionCoversAllSensitiveTables) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) {
        master_key[i] = static_cast<std::uint8_t>(0xa0 + i);
    }
    const std::string canary_session = "SESSION_BLOB_CANARY_AAAAAAAA";
    const std::string canary_chan_dist = "CHAN_DIST_CANARY_BBBBBBBB";
    const std::string canary_peer_dist = "PEER_DIST_CANARY_CCCCCCCC";
    const std::string canary_chan_msg = "CHAN_MSG_CANARY_DDDDDDDD";
    const std::string canary_username = "CANARY_USERNAME_EEEEEEEE";
    auto peer_pub = bytes({0x01, 0x02, 0x03, 0x04});
    auto chan_id = bytes({0x10, 0x11, 0x12, 0x13});
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        std::vector<std::uint8_t> v;
        v.assign(canary_session.begin(),    canary_session.end());
        s->save_session(span_of(peer_pub), span_of(v));
        v.assign(canary_chan_dist.begin(),  canary_chan_dist.end());
        s->chan_save("general", span_of(chan_id), span_of(v));
        v.assign(canary_peer_dist.begin(),  canary_peer_dist.end());
        s->chan_save_peer(span_of(chan_id), span_of(peer_pub), span_of(v));
        v.assign(canary_chan_msg.begin(),   canary_chan_msg.end());
        s->chan_append_inbox(span_of(chan_id), span_of(peer_pub), span_of(v),
                              42);
        s->cache_peer_name(span_of(peer_pub), canary_username);
    }
    // Re-open under the same key; every read returns the canary.
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        auto sess = s->load_session(span_of(peer_pub));
        ASSERT_TRUE(sess.has_value());
        EXPECT_EQ(std::string(sess->begin(), sess->end()), canary_session);

        auto chans = s->chan_list();
        ASSERT_EQ(chans.size(), 1u);
        EXPECT_EQ(std::string(chans[0].own_dist.begin(), chans[0].own_dist.end()),
                  canary_chan_dist);

        auto peers = s->chan_peers(span_of(chan_id));
        ASSERT_EQ(peers.size(), 1u);
        EXPECT_EQ(std::string(peers[0].peer_dist.begin(),
                              peers[0].peer_dist.end()),
                  canary_peer_dist);

        auto msgs = s->chan_recent_inbox(span_of(chan_id), 10);
        ASSERT_EQ(msgs.size(), 1u);
        EXPECT_EQ(std::string(msgs[0].plaintext.begin(),
                              msgs[0].plaintext.end()),
                  canary_chan_msg);

        EXPECT_EQ(*s->peer_name(span_of(peer_pub)), canary_username);
    }
    // None of the canaries appear in the raw on-disk bytes.
    FILE* f = std::fopen(path.c_str(), "rb");
    ASSERT_NE(f, nullptr);
    std::fseek(f, 0, SEEK_END);
    const long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<char> file(static_cast<std::size_t>(sz));
    ASSERT_EQ(std::fread(file.data(), 1, file.size(), f), file.size());
    std::fclose(f);
    const auto blob = std::string_view(file.data(), file.size());
    for (const auto& canary : {canary_session, canary_chan_dist,
                                canary_peer_dist, canary_chan_msg,
                                canary_username}) {
        EXPECT_EQ(blob.find(canary), std::string_view::npos)
            << "leaked through to disk: " << canary;
    }
}

// MLS group save / append / load round trip on an encrypted DB:
// stores a seed + 3 op blobs under one channel_id, closes & reopens
// the DB with the same key, and verifies the plaintext seed and ops
// (in seq order) come back intact via mls_group_load. Also confirms
// that next_seq advances past the highest stored seq (so the caller
// can keep appending).
TEST_F(TmpDb, MlsGroupPersistenceRoundTripEncrypted) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) master_key[i] = 0x42;
    std::vector<std::uint8_t> channel_id(32, 0x77);
    auto seed = bytes({0x01, 0x02, 0x03, 0x04, 0x05});
    auto op0  = bytes({0xaa});
    auto op1  = bytes({0xbb, 0xbb});
    auto op2  = bytes({0xcc, 0xcc, 0xcc});

    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        s->mls_group_save(span_of(channel_id), span_of(seed));
        s->mls_group_op_append(span_of(channel_id), 0, span_of(op0));
        s->mls_group_op_append(span_of(channel_id), 1, span_of(op1));
        s->mls_group_op_append(span_of(channel_id), 2, span_of(op2));
    }
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        auto snap = s->mls_group_load(span_of(channel_id));
        ASSERT_TRUE(snap.has_value());
        EXPECT_EQ(snap->seed, seed);
        ASSERT_EQ(snap->ops.size(), 3u);
        EXPECT_EQ(snap->ops[0], op0);
        EXPECT_EQ(snap->ops[1], op1);
        EXPECT_EQ(snap->ops[2], op2);
        EXPECT_EQ(snap->next_seq, 3);
    }
}

// mls_group_save is upsert: a second save for the same channel_id
// replaces the seed. Used at re-creation or re-join time.
TEST_F(TmpDb, MlsGroupSaveReplacesSeed) {
    auto s = fb::store::SqliteStore::open(path);
    std::vector<std::uint8_t> channel_id(32, 0x33);
    auto seed_a = bytes({0x01, 0x01});
    auto seed_b = bytes({0x02, 0x02, 0x02});
    s->mls_group_save(span_of(channel_id), span_of(seed_a));
    s->mls_group_save(span_of(channel_id), span_of(seed_b));
    auto snap = s->mls_group_load(span_of(channel_id));
    ASSERT_TRUE(snap.has_value());
    EXPECT_EQ(snap->seed, seed_b);
    EXPECT_TRUE(snap->ops.empty());
}

// Loading a non-existent channel returns nullopt — important
// because chat_client uses presence-vs-absence to distinguish
// "MLS channel that needs restore" from "MLS channel never seen".
TEST_F(TmpDb, MlsGroupLoadMissingReturnsNullopt) {
    auto s = fb::store::SqliteStore::open(path);
    std::vector<std::uint8_t> channel_id(32, 0x22);
    EXPECT_FALSE(s->mls_group_load(span_of(channel_id)).has_value());
}

// chan_delete cleans up mls_group_state + mls_group_log too.
TEST_F(TmpDb, ChanDeleteAlsoDropsMlsTables) {
    auto s = fb::store::SqliteStore::open(path);
    std::vector<std::uint8_t> channel_id(32, 0x55);
    s->chan_save("hangout", span_of(channel_id), {},
                 fb::store::SqliteStore::ChannelCrypto::kMls);
    s->mls_group_save(span_of(channel_id), bytes({0xaa, 0xbb}));
    s->mls_group_op_append(span_of(channel_id), 0, bytes({0xcc}));
    EXPECT_TRUE(s->mls_group_load(span_of(channel_id)).has_value());

    s->chan_delete("hangout", span_of(channel_id));
    EXPECT_FALSE(s->mls_group_load(span_of(channel_id)).has_value());
}

// Reopening an encrypted DB with NO key throws — protects against
// silently treating the wrapped blobs as plaintext.
TEST_F(TmpDb, AtRestRefusesUnkeyedReopen) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) master_key[i] = 0x42;
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        auto envid = bytes({0xaa});
        auto peer  = bytes({0xbb});
        auto pt    = bytes({0xcc, 0xdd});
        s->append_inbox(span_of(envid), span_of(peer), span_of(pt), 1);
    }
    EXPECT_THROW({
        auto s = fb::store::SqliteStore::open(path);
    }, std::runtime_error);
}
