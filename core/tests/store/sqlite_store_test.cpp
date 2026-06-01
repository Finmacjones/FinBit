// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/store/sqlite_store.hpp"
#include "fb/store/attachment_frame.hpp"

#include <gtest/gtest.h>
#include <sqlite3.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <span>
#include <string>
#include <thread>
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

// Read the raw (still-AEAD-wrapped) inbox.plaintext blob for one envelope_id
// directly off disk via a fresh sqlite3 connection — used to prove the master
// ratchet actually re-encrypted the row on disk (the stored bytes change).
std::vector<std::uint8_t> raw_inbox_blob(const std::string& path,
                                         const std::vector<std::uint8_t>& envid) {
    sqlite3* db = nullptr;
    std::vector<std::uint8_t> out;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) { sqlite3_close(db); return out; }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT plaintext FROM inbox WHERE envelope_id = ?;", -1, &st,
            nullptr) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, envid.data(), static_cast<int>(envid.size()),
                          SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const auto* p = static_cast<const std::uint8_t*>(
                sqlite3_column_blob(st, 0));
            const int n = sqlite3_column_bytes(st, 0);
            out.assign(p, p + n);
        }
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return out;
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

// F1 regression: peer_pubkeys_for_username locks the recursive_mutex then
// calls all_cached_peers (which re-locks it). With a non-recursive mutex
// this self-deadlocks; this test would hang. It passing proves the lock
// is recursive as required.
TEST_F(TmpDb, RecursiveLockDoesNotSelfDeadlock) {
    auto s = fb::store::SqliteStore::open(path);
    auto pub = bytes({0xaa});
    s->cache_peer_name(span_of(pub), "bob");
    auto pubs = s->peer_pubkeys_for_username("bob");   // re-enters all_cached_peers
    ASSERT_EQ(pubs.size(), 1u);
    EXPECT_EQ(pubs[0], std::vector<std::uint8_t>{0xaa});
}

// F1 regression: concurrent writer (worker-thread role) + reader
// (UI-thread role) hammering the SAME store. Without the Impl mutex +
// busy_timeout this races on the table sub-keys / throws SQLITE_BUSY.
// Run with an at-rest key so rotate_storage_keys exercises the sub-key
// swap the audit flagged as a torn-read hazard. TSan-clean if the lock
// covers it.
TEST_F(TmpDb, ConcurrentWriterReaderIsSafe) {
    std::array<std::uint8_t, 32> mk{};
    for (auto& b : mk) b = 0x5a;
    auto s = fb::store::SqliteStore::open(path,
        std::span<const std::uint8_t>(mk.data(), mk.size()));
    auto peer = bytes({0xc0, 0xff, 0xee});
    // Seed some rows so rotate + reads have content.
    for (int i = 0; i < 20; ++i) {
        auto id = bytes({static_cast<std::uint8_t>(i)});
        auto pt = bytes({static_cast<std::uint8_t>(i), 0x11, 0x22});
        s->append_inbox(span_of(id), span_of(peer), span_of(pt),
                        static_cast<std::uint64_t>(1000 + i));
    }

    std::atomic<bool> stop{false};
    std::atomic<int> reads{0};
    // Reader thread: continuously read inbox + rotate-affected tables.
    std::thread reader([&] {
        while (!stop.load()) {
            auto rows = s->recent_inbox(50);
            // Every row's plaintext must be intact — a torn sub-key read
            // during a concurrent rotate would corrupt the AEAD decrypt
            // and either throw or yield wrong bytes.
            for (const auto& r : rows) {
                ASSERT_EQ(r.plaintext.size(), 3u);
                ASSERT_EQ(r.plaintext[1], 0x11);
                ASSERT_EQ(r.plaintext[2], 0x22);
            }
            reads.fetch_add(1);
        }
    });
    // Writer thread: rotate keys repeatedly (the high-risk path).
    for (int i = 0; i < 25; ++i) {
        EXPECT_NO_THROW({ (void)s->rotate_storage_keys(); });
    }
    stop.store(true);
    reader.join();
    EXPECT_GT(reads.load(), 0);
    // After all the rotations, rows still decrypt correctly.
    auto final_rows = s->recent_inbox(50);
    EXPECT_EQ(final_rows.size(), 20u);
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

// An inline attachment persists through the encrypted store as a framed
// blob and reloads byte-identical (this is the image-history claim). The
// raw image bytes (incl. a canary) must not leak into the .db file.
TEST_F(TmpDb, AttachmentFramePersistsThroughEncryptedStore) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i)
        master_key[i] = static_cast<std::uint8_t>(i * 3 + 1);
    const std::string canary = "IMG_CANARY_PNGDATA_QWERTY";
    std::vector<std::uint8_t> content(canary.begin(), canary.end());
    content.insert(content.end(), {0x00, 0xff, 0x10, 0x20});  // binary tail
    auto envid = bytes({0x42, 0x43, 0x44, 0x45});
    auto peer  = bytes({0x50, 0x51, 0x52, 0x53});
    const auto framed = fb::store::frame_attachment("image/png", "shot.png",
        std::span<const std::uint8_t>(content.data(), content.size()));
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        s->append_inbox(span_of(envid), span_of(peer), span_of(framed), 999);
    }
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        auto rows = s->recent_inbox(10);
        ASSERT_EQ(rows.size(), 1u);
        auto at = fb::store::parse_attachment_frame(
            std::span<const std::uint8_t>(rows[0].plaintext.data(),
                                          rows[0].plaintext.size()));
        ASSERT_TRUE(at.has_value());
        EXPECT_EQ(at->mime, "image/png");
        EXPECT_EQ(at->filename, "shot.png");
        EXPECT_EQ(at->content, content);
    }
    // The image content canary must not appear on disk in cleartext.
    FILE* f = std::fopen(path.c_str(), "rb");
    ASSERT_NE(f, nullptr);
    std::fseek(f, 0, SEEK_END);
    const long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<char> file(static_cast<std::size_t>(sz));
    ASSERT_EQ(std::fread(file.data(), 1, file.size(), f), file.size());
    std::fclose(f);
    EXPECT_EQ(std::string_view(file.data(), file.size()).find(canary),
              std::string_view::npos)
        << "attachment content leaked into the .db file in cleartext";
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

// ---- Tier-11 forward-secret local storage (TTL + prune_expired) ----------

TEST_F(TmpDb, AppendWithExpiryAndPruneRemovesPastDueRows) {
    auto s = fb::store::SqliteStore::open(path);
    auto peer = bytes({0xbe, 0xef});
    auto pt   = bytes({0x01, 0x02, 0x03});

    // Three rows: two expire at 1000ms, one expires at 5000ms,
    // one never expires (legacy append_inbox).
    auto id1 = bytes({0x01});
    auto id2 = bytes({0x02});
    auto id3 = bytes({0x03});
    auto id4 = bytes({0x04});
    s->append_inbox_with_expiry(span_of(id1), span_of(peer), span_of(pt), 100, 1000);
    s->append_inbox_with_expiry(span_of(id2), span_of(peer), span_of(pt), 200, 1000);
    s->append_outbox_with_expiry(span_of(id3), span_of(peer), span_of(pt), 300, 5000);
    s->append_inbox(span_of(id4), span_of(peer), span_of(pt), 400);   // never expires

    // Sweep at now = 2000ms — id1+id2 (expired) get deleted; id3 and id4 survive.
    EXPECT_EQ(s->prune_expired(2000), 2u);
    auto inbox = s->recent_inbox(100);
    EXPECT_EQ(inbox.size(), 1u);
    EXPECT_EQ(inbox.front().envelope_id, std::vector<std::uint8_t>{0x04});

    // Sweep at now = 6000ms — id3 (expires at 5000) goes.
    EXPECT_EQ(s->prune_expired(6000), 1u);
}

TEST_F(TmpDb, PruneExpiredIsNoOpWhenNothingDue) {
    auto s = fb::store::SqliteStore::open(path);
    auto peer = bytes({0xff});
    auto pt   = bytes({0xaa});
    auto id   = bytes({0x99});
    s->append_inbox_with_expiry(span_of(id), span_of(peer), span_of(pt), 100, 5000);
    EXPECT_EQ(s->prune_expired(1000), 0u);
    EXPECT_EQ(s->recent_inbox(100).size(), 1u);
}

TEST_F(TmpDb, LegacyAppendNeverExpires) {
    auto s = fb::store::SqliteStore::open(path);
    auto peer = bytes({0xee});
    auto pt   = bytes({0xbb});
    auto id   = bytes({0x77});
    s->append_inbox(span_of(id), span_of(peer), span_of(pt), 100);
    // Sweep arbitrarily far into the future — legacy row (expires_at_ms = 0) survives.
    EXPECT_EQ(s->prune_expired(std::uint64_t{1} << 60), 0u);
    EXPECT_EQ(s->recent_inbox(100).size(), 1u);
}

// ---- Tier-11 Shamir held-share custody -------------------------------------

TEST_F(TmpDb, SaveAndLoadShamirShareRoundTrip) {
    auto s = fb::store::SqliteStore::open(path);
    fb::store::SqliteStore::ShamirHeldShare h;
    h.peer_pub.assign({0xaa, 0xbb, 0xcc});
    h.setup_id       = 0xdeadbeef;
    h.share.assign({0x01, 0x02, 0x03, 0x04, 0x05});
    h.threshold      = 3;
    h.total          = 5;
    h.label          = "primary";
    h.received_at_ms = 100000;
    s->save_shamir_share(h);

    auto loaded = s->load_shamir_share(
        std::span<const std::uint8_t>(h.peer_pub.data(), h.peer_pub.size()),
        h.setup_id);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->peer_pub, h.peer_pub);
    EXPECT_EQ(loaded->setup_id, h.setup_id);
    EXPECT_EQ(loaded->share,    h.share);
    EXPECT_EQ(loaded->threshold, 3u);
    EXPECT_EQ(loaded->total,     5u);
    EXPECT_EQ(loaded->label,    "primary");
    EXPECT_EQ(loaded->received_at_ms, 100000u);
}

TEST_F(TmpDb, ShamirShareCompositeKeyAllowsMultipleSetupsPerPeer) {
    auto s = fb::store::SqliteStore::open(path);
    fb::store::SqliteStore::ShamirHeldShare a, b;
    a.peer_pub = b.peer_pub = bytes({0x11}).empty() ? std::vector<std::uint8_t>{0x11} : std::vector<std::uint8_t>{0x11};
    a.peer_pub = {0x11}; b.peer_pub = {0x11};
    a.setup_id = 1; b.setup_id = 2;
    a.share = {0xa}; b.share = {0xb};
    a.threshold = a.total = b.threshold = b.total = 2;
    a.received_at_ms = 10; b.received_at_ms = 20;
    s->save_shamir_share(a);
    s->save_shamir_share(b);
    EXPECT_EQ(s->list_shamir_shares().size(), 2u);

    auto la = s->load_shamir_share(
        std::span<const std::uint8_t>(a.peer_pub.data(), a.peer_pub.size()), 1);
    auto lb = s->load_shamir_share(
        std::span<const std::uint8_t>(b.peer_pub.data(), b.peer_pub.size()), 2);
    ASSERT_TRUE(la.has_value());
    ASSERT_TRUE(lb.has_value());
    EXPECT_EQ(la->share, std::vector<std::uint8_t>{0xa});
    EXPECT_EQ(lb->share, std::vector<std::uint8_t>{0xb});
}

TEST_F(TmpDb, ShamirShareUpsertReplacesPrior) {
    auto s = fb::store::SqliteStore::open(path);
    fb::store::SqliteStore::ShamirHeldShare h;
    h.peer_pub = {0x22}; h.setup_id = 1;
    h.share = {0xc0}; h.threshold = h.total = 1; h.received_at_ms = 1;
    s->save_shamir_share(h);

    // Same composite key — different share bytes (rotation / re-setup).
    h.share = {0xc1, 0xc2};
    h.received_at_ms = 2;
    s->save_shamir_share(h);
    auto loaded = s->load_shamir_share(
        std::span<const std::uint8_t>(h.peer_pub.data(), h.peer_pub.size()), 1);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->share, (std::vector<std::uint8_t>{0xc1, 0xc2}));
    EXPECT_EQ(loaded->received_at_ms, 2u);
    EXPECT_EQ(s->list_shamir_shares().size(), 1u);
}

TEST_F(TmpDb, ShamirShareMissingLookupReturnsNullopt) {
    auto s = fb::store::SqliteStore::open(path);
    auto p = bytes({0xff});
    EXPECT_FALSE(s->load_shamir_share(span_of(p), 42).has_value());
    EXPECT_TRUE(s->list_shamir_shares().empty());
}

// ---- Tier-11 Phase 2 — storage-key rotation -------------------------------

TEST_F(TmpDb, RotateStorageKeysPreservesAllRows) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) master_key[i] = 0x77;
    auto s = fb::store::SqliteStore::open(path,
        std::span<const std::uint8_t>(master_key.data(), master_key.size()));

    // Seed: 3 inbox + 2 outbox + 1 session row.
    auto peer = bytes({0xab, 0xcd});
    auto pt_a = bytes({1, 2, 3});
    auto pt_b = bytes({4, 5, 6, 7});
    auto pt_c = bytes({8, 9});
    auto sess = bytes({0x11, 0x22, 0x33, 0x44});
    auto id1 = bytes({0xa1}), id2 = bytes({0xa2}), id3 = bytes({0xa3});
    auto id4 = bytes({0xb1}), id5 = bytes({0xb2});
    s->append_inbox(span_of(id1), span_of(peer), span_of(pt_a), 1000);
    s->append_inbox(span_of(id2), span_of(peer), span_of(pt_b), 2000);
    s->append_inbox(span_of(id3), span_of(peer), span_of(pt_c), 3000);
    s->append_outbox(span_of(id4), span_of(peer), span_of(pt_a), 4000);
    s->append_outbox(span_of(id5), span_of(peer), span_of(pt_b), 5000);
    s->save_session(span_of(peer), span_of(sess));

    // Rotate. Returns count of rows re-wrapped.
    EXPECT_EQ(s->rotate_storage_keys(), 6u);   // 3 inbox + 2 outbox + 1 session

    // All rows still readable + plaintext intact (the rotation re-wrapped
    // under fresh sub-keys, but the same master_key unwraps them via the
    // persisted storage_keys table).
    auto inbox = s->recent_inbox(10);
    ASSERT_EQ(inbox.size(), 3u);
    // Sorted DESC by ts — newest first.
    EXPECT_EQ(inbox[0].plaintext, pt_c);
    EXPECT_EQ(inbox[1].plaintext, pt_b);
    EXPECT_EQ(inbox[2].plaintext, pt_a);
    auto outbox = s->recent_outbox(10);
    ASSERT_EQ(outbox.size(), 2u);
    auto loaded_sess = s->load_session(span_of(peer));
    ASSERT_TRUE(loaded_sess.has_value());
    EXPECT_EQ(*loaded_sess, sess);
}

TEST_F(TmpDb, RotateStorageKeysSurvivesReopen) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) master_key[i] = 0x99;
    auto peer = bytes({0x01, 0x02});
    auto pt   = bytes({0x42, 0x43, 0x44});
    auto id   = bytes({0xde, 0xad});
    {
        auto s = fb::store::SqliteStore::open(path,
            std::span<const std::uint8_t>(master_key.data(), master_key.size()));
        s->append_inbox(span_of(id), span_of(peer), span_of(pt), 1000);
        EXPECT_EQ(s->rotate_storage_keys(), 1u);
    }
    // Reopen with the same master → the persisted (rotated) sub-keys
    // are unwrapped from `storage_keys` and used for subsequent reads.
    auto s2 = fb::store::SqliteStore::open(path,
        std::span<const std::uint8_t>(master_key.data(), master_key.size()));
    auto inbox = s2->recent_inbox(10);
    ASSERT_EQ(inbox.size(), 1u);
    EXPECT_EQ(inbox.front().plaintext, pt);
}

TEST_F(TmpDb, RotateStorageKeysIsRepeatableAndRowsAlwaysReadable) {
    std::array<std::uint8_t, 32> master_key{};
    for (std::size_t i = 0; i < master_key.size(); ++i) master_key[i] = 0x55;
    auto s = fb::store::SqliteStore::open(path,
        std::span<const std::uint8_t>(master_key.data(), master_key.size()));

    auto peer = bytes({0xfe});
    auto pt   = bytes({0xaa, 0xbb});
    auto id1  = bytes({0x01});
    auto id2  = bytes({0x02});
    s->append_inbox(span_of(id1), span_of(peer), span_of(pt), 100);

    // First rotation moves the row from gen 0 → gen 1.
    EXPECT_EQ(s->rotate_storage_keys(), 1u);
    // Append a row under the new sub-keys.
    s->append_inbox(span_of(id2), span_of(peer), span_of(pt), 200);
    // Second rotation moves both rows from gen 1 → gen 2.
    EXPECT_EQ(s->rotate_storage_keys(), 2u);

    auto inbox = s->recent_inbox(10);
    ASSERT_EQ(inbox.size(), 2u);
    EXPECT_EQ(inbox[0].plaintext, pt);
    EXPECT_EQ(inbox[1].plaintext, pt);
}

TEST_F(TmpDb, RotateStorageKeysIsNoopWhenUnencrypted) {
    auto s = fb::store::SqliteStore::open(path);   // no master key
    auto peer = bytes({0xee});
    auto pt   = bytes({0x10});
    auto id   = bytes({0x55});
    s->append_inbox(span_of(id), span_of(peer), span_of(pt), 100);
    EXPECT_EQ(s->rotate_storage_keys(), 0u);
    EXPECT_EQ(s->recent_inbox(10).size(), 1u);
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

// TOFU PQ-capability pin (audit residual). Default is "not capable"; once
// pinned it is sticky (a later capable=false can't downgrade it), and the pin
// survives a reopen so an attacker can't beat it by waiting for a restart.
TEST_F(TmpDb, PeerPqCapablePinIsStickyAndPersists) {
    auto peer = bytes({0xab, 0xcd, 0xef, 0x01});
    {
        auto s = fb::store::SqliteStore::open(path);
        EXPECT_FALSE(s->peer_pq_capable(span_of(peer)));   // unknown peer
        s->set_peer_pq_capable(span_of(peer), true, 1000);
        EXPECT_TRUE(s->peer_pq_capable(span_of(peer)));
        // A clearing attempt must NOT downgrade the sticky pin.
        s->set_peer_pq_capable(span_of(peer), false, 2000);
        EXPECT_TRUE(s->peer_pq_capable(span_of(peer)));
    }
    // Reopen: the pin persists across restart.
    {
        auto s = fb::store::SqliteStore::open(path);
        EXPECT_TRUE(s->peer_pq_capable(span_of(peer)));
        // A different, never-seen peer is still not capable.
        auto other = bytes({0x99, 0x88});
        EXPECT_FALSE(s->peer_pq_capable(span_of(other)));
    }
}

// Forward-secret storage MASTER ratchet (audit residual). Re-keys every
// encrypted table under a fresh random master, persists it wrapped under the
// KEK, and the new master is recovered from disk on reopen.
TEST_F(TmpDb, MasterRatchetReKeysAndSurvivesReopen) {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i + 1);
    auto K = std::span<const std::uint8_t>(key.data(), key.size());
    auto envid = bytes({0x01, 0x02}); auto peer = bytes({0x0a, 0x0b});
    const std::string c_inbox = "RATCHET_INBOX_CANARY";
    const std::string c_sess  = "RATCHET_SESSION_CANARY";
    const std::string c_name  = "RATCHET_NAME_CANARY";
    {
        auto s = fb::store::SqliteStore::open(path, K);
        std::vector<std::uint8_t> pt(c_inbox.begin(), c_inbox.end());
        s->append_inbox(span_of(envid), span_of(peer), span_of(pt), 111);
        std::vector<std::uint8_t> sb(c_sess.begin(), c_sess.end());
        s->save_session(span_of(peer), span_of(sb));
        s->cache_peer_name(span_of(peer), c_name);
        EXPECT_EQ(s->storage_master_generation(), 0u);
        const auto n = s->ratchet_storage_master();
        EXPECT_GT(n, 0u);
        EXPECT_EQ(s->storage_master_generation(), 1u);
        // Readable in-memory immediately after the ratchet (new keys live).
        auto rows = s->recent_inbox(10);
        ASSERT_EQ(rows.size(), 1u);
        EXPECT_EQ(std::string(rows[0].plaintext.begin(), rows[0].plaintext.end()), c_inbox);
        auto sess = s->load_session(span_of(peer));
        ASSERT_TRUE(sess.has_value());
        EXPECT_EQ(std::string(sess->begin(), sess->end()), c_sess);
        EXPECT_EQ(*s->peer_name(span_of(peer)), c_name);
    }
    // Reopen with the SAME key: the fresh random master is recovered off disk.
    {
        auto s = fb::store::SqliteStore::open(path, K);
        EXPECT_EQ(s->storage_master_generation(), 1u);
        auto rows = s->recent_inbox(10);
        ASSERT_EQ(rows.size(), 1u);
        EXPECT_EQ(std::string(rows[0].plaintext.begin(), rows[0].plaintext.end()), c_inbox);
        EXPECT_EQ(*s->peer_name(span_of(peer)), c_name);
        // Ratchet a second epoch (master is now random→random, not KEK→random).
        EXPECT_GT(s->ratchet_storage_master(), 0u);
        EXPECT_EQ(s->storage_master_generation(), 2u);
    }
    {
        auto s = fb::store::SqliteStore::open(path, K);
        EXPECT_EQ(s->storage_master_generation(), 2u);
        auto sess = s->load_session(span_of(peer));
        ASSERT_TRUE(sess.has_value());
        EXPECT_EQ(std::string(sess->begin(), sess->end()), c_sess);
    }
}

// The ratchet must actually RE-ENCRYPT rows on disk (the stored ciphertext
// changes), and the plaintext stays absent from the raw file the whole time.
TEST_F(TmpDb, MasterRatchetReEncryptsOnDiskAndStaysEncrypted) {
    std::array<std::uint8_t, 32> key{};
    for (auto& b : key) b = 0x33;
    auto K = std::span<const std::uint8_t>(key.data(), key.size());
    auto envid = bytes({0x77, 0x88}); auto peer = bytes({0x99});
    const std::string canary = "REKEY_DISK_CANARY_ZZZZ";
    {
        auto s = fb::store::SqliteStore::open(path, K);
        std::vector<std::uint8_t> pt(canary.begin(), canary.end());
        s->append_inbox(span_of(envid), span_of(peer), span_of(pt), 5);
    }
    const auto b0 = raw_inbox_blob(path, envid);
    ASSERT_FALSE(b0.empty());
    {
        auto s = fb::store::SqliteStore::open(path, K);
        EXPECT_GT(s->ratchet_storage_master(), 0u);
    }
    const auto b1 = raw_inbox_blob(path, envid);
    ASSERT_FALSE(b1.empty());
    EXPECT_NE(b0, b1) << "ratchet must re-encrypt the row under the new master";
    // Still decryptable via the API.
    {
        auto s = fb::store::SqliteStore::open(path, K);
        auto rows = s->recent_inbox(10);
        ASSERT_EQ(rows.size(), 1u);
        EXPECT_EQ(std::string(rows[0].plaintext.begin(), rows[0].plaintext.end()), canary);
    }
    // The plaintext canary must NOT be present anywhere in the raw file.
    FILE* f = std::fopen(path.c_str(), "rb");
    ASSERT_NE(f, nullptr);
    std::fseek(f, 0, SEEK_END);
    const long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<char> file(static_cast<std::size_t>(sz));
    ASSERT_EQ(std::fread(file.data(), 1, file.size(), f), file.size());
    std::fclose(f);
    EXPECT_EQ(std::string_view(file.data(), file.size()).find(canary),
              std::string_view::npos)
        << "plaintext leaked into the .db after the ratchet";
}

// After a ratchet, the storage master is a random value wrapped under the KEK,
// so reopening with the WRONG key must fail loudly (not derive garbage keys).
TEST_F(TmpDb, MasterRatchetBindsToKekWrongKeyThrows) {
    std::array<std::uint8_t, 32> key{};
    for (auto& b : key) b = 0x42;
    auto K = std::span<const std::uint8_t>(key.data(), key.size());
    auto envid = bytes({0x01}); auto peer = bytes({0x02});
    {
        auto s = fb::store::SqliteStore::open(path, K);
        auto pt = bytes({0xcc, 0xdd});
        s->append_inbox(span_of(envid), span_of(peer), span_of(pt), 1);
        EXPECT_GT(s->ratchet_storage_master(), 0u);
    }
    // Right key still opens.
    {
        auto s = fb::store::SqliteStore::open(path, K);
        EXPECT_EQ(s->storage_master_generation(), 1u);
    }
    // Wrong key: storage_master won't unwrap → throw.
    std::array<std::uint8_t, 32> wrong{};
    for (auto& b : wrong) b = 0xff;
    EXPECT_THROW({
        auto s = fb::store::SqliteStore::open(
            path, std::span<const std::uint8_t>(wrong.data(), wrong.size()));
    }, std::runtime_error);
}

// Ratcheting a plaintext (unencrypted) store is a no-op.
TEST_F(TmpDb, MasterRatchetNoopWhenUnencrypted) {
    auto s = fb::store::SqliteStore::open(path);   // no key
    EXPECT_EQ(s->ratchet_storage_master(), 0u);
    EXPECT_EQ(s->storage_master_generation(), 0u);
}

// The ratchet must also re-key the MLS tables (state + log) — the log uses a
// channel_id||seq_be AAD, so this exercises the inline re-encryption path and
// guards against silently bricking MLS group history on a master ratchet.
TEST_F(TmpDb, MasterRatchetReKeysMlsTables) {
    std::array<std::uint8_t, 32> key{};
    for (auto& b : key) b = 0x5a;
    auto K = std::span<const std::uint8_t>(key.data(), key.size());
    std::vector<std::uint8_t> channel_id(32, 0x71);
    auto seed = bytes({0x10, 0x11, 0x12});
    auto op0  = bytes({0xa0});
    auto op1  = bytes({0xb1, 0xb1});
    {
        auto s = fb::store::SqliteStore::open(path, K);
        s->mls_group_save(span_of(channel_id), span_of(seed));
        s->mls_group_op_append(span_of(channel_id), 0, span_of(op0));
        s->mls_group_op_append(span_of(channel_id), 1, span_of(op1));
        EXPECT_GT(s->ratchet_storage_master(), 0u);
        // Readable immediately after the ratchet.
        auto snap = s->mls_group_load(span_of(channel_id));
        ASSERT_TRUE(snap.has_value());
        EXPECT_EQ(snap->seed, seed);
        ASSERT_EQ(snap->ops.size(), 2u);
        EXPECT_EQ(snap->ops[0], op0);
        EXPECT_EQ(snap->ops[1], op1);
    }
    // Recovered intact after reopen under the ratcheted master.
    {
        auto s = fb::store::SqliteStore::open(path, K);
        EXPECT_EQ(s->storage_master_generation(), 1u);
        auto snap = s->mls_group_load(span_of(channel_id));
        ASSERT_TRUE(snap.has_value());
        EXPECT_EQ(snap->seed, seed);
        ASSERT_EQ(snap->ops.size(), 2u);
        EXPECT_EQ(snap->ops[0], op0);
        EXPECT_EQ(snap->ops[1], op1);
        EXPECT_EQ(snap->next_seq, 2);
    }
}
