// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// MLS persistence integration test.
//
// Exercises the full save → close → reopen → restore → encrypt/decrypt loop
// across the wrapper (fb::crypto::MlsGroup) and the on-disk store
// (fb::store::SqliteStore). The unit tests in mls_facade_test.cpp prove
// MlsGroup serializes/restores correctly given an in-memory blob; the
// sqlite_store_test.cpp tests prove the tables round-trip seed + ops; this
// test wires the two halves together and verifies the combination
// produces a usable post-restart group at the same epoch as the live one.
//
// Two scenarios:
//   1. Creator-only (no commits, just encrypt/decrypt at epoch 0).
//   2. Two-member with one Add commit + multi-message back-and-forth
//      across the simulated restart on BOTH sides (alice + bob each
//      independently restored from their own DB).
//
// Both are FB_HAVE_MLS-only (the stub build can't construct MlsGroup).
// =============================================================================

#include "fb/crypto/mls_facade.hpp"
#include "fb/store/sqlite_store.hpp"

#include <gtest/gtest.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#if FB_HAVE_MLS

namespace {

struct MlsPersistTmpDb : ::testing::Test {
    std::string path;
    void SetUp() override {
        char tmpl[] = "/tmp/fb_mls_persist_XXXXXX.db";
        const int fd = mkstemps(tmpl, 3);
        ASSERT_GE(fd, 0);
        ::close(fd);
        path = tmpl;
    }
    void TearDown() override {
        if (!path.empty()) ::unlink(path.c_str());
    }
};

std::array<std::uint8_t, 32> id_seed(std::uint8_t fill) {
    std::array<std::uint8_t, 32> out{};
    for (auto& b : out) b = fill;
    return out;
}

std::span<const std::uint8_t> as_span(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

void persist_seed(fb::store::SqliteStore& s,
                  const std::array<std::uint8_t, 32>& chan_id,
                  fb::crypto::MlsGroup& g) {
    auto seed = g.serialize_seed();
    s.mls_group_save(std::span<const std::uint8_t>(chan_id.data(), 32),
                     as_span(seed));
}

// Drain g.operation_log() into the store starting at next_seq, return
// the new next_seq. Equivalent to repeatedly calling persist_mls_last_op
// (the lambda inside ChatClient) for each newly-appended op.
std::int64_t persist_all_ops(fb::store::SqliteStore& s,
                              const std::array<std::uint8_t, 32>& chan_id,
                              fb::crypto::MlsGroup& g,
                              std::int64_t starting_seq) {
    auto ops = g.operation_log();
    auto seq = starting_seq;
    for (std::size_t i = static_cast<std::size_t>(starting_seq);
         i < ops.size(); ++i, ++seq) {
        s.mls_group_op_append(
            std::span<const std::uint8_t>(chan_id.data(), 32),
            seq,
            as_span(ops[i]));
    }
    return seq;
}

}  // namespace

// Creator at epoch 0, no peers — proves the seed alone (no commits)
// round-trips through the store and the restored group can encrypt
// to itself decryptably.
TEST_F(MlsPersistTmpDb, MlsPersistence_CreatorRoundTrip) {
    auto identity = id_seed(0xa1);
    auto chan_id  = id_seed(0x42);

    {
        auto store = fb::store::SqliteStore::open(path);
        auto live = fb::crypto::MlsGroup::create(
            std::span<const std::uint8_t, 32>(identity),
            std::span<const std::uint8_t, 32>(chan_id));
        persist_seed(*store, chan_id, *live);
    }

    auto store = fb::store::SqliteStore::open(path);
    auto snap = store->mls_group_load(
        std::span<const std::uint8_t>(chan_id.data(), 32));
    ASSERT_TRUE(snap.has_value());
    EXPECT_TRUE(snap->ops.empty());
    EXPECT_EQ(snap->next_seq, 0);

    auto restored = fb::crypto::MlsGroup::from_seed_and_log(
        as_span(snap->seed), snap->ops);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->member_count(), 1u);

    // Cross-restart self-decrypt: encrypt under one restoration,
    // decrypt under another rebuilt from the same on-disk state.
    auto restored2 = fb::crypto::MlsGroup::from_seed_and_log(
        as_span(snap->seed), snap->ops);
    const std::string text = "hello from beyond the restart boundary";
    std::vector<std::uint8_t> pt(text.begin(), text.end());
    auto ct = restored->application_encrypt(as_span(pt));
    auto round = restored2->application_decrypt(as_span(ct));
    ASSERT_TRUE(round.has_value());
    EXPECT_EQ(*round, pt);
}

// Two-member end-to-end: alice creates + persists, alice adds bob
// (1 commit appended), bob completes via Welcome and persists his
// joiner seed. Both DBs are then closed. Both reopen, restore, and
// decrypt a fresh message produced by the OTHER side. This is the
// load-bearing scenario the persistence layer exists for.
TEST_F(MlsPersistTmpDb, MlsPersistence_TwoMemberRoundTripAcrossRestart) {
    // Two separate DB files — one per simulated user. Avoids the
    // need for a shared-store coordination protocol.
    std::string alice_path = path;
    char tmpl[] = "/tmp/fb_mls_persist_b_XXXXXX.db";
    const int fd = mkstemps(tmpl, 3);
    ASSERT_GE(fd, 0);
    ::close(fd);
    std::string bob_path = tmpl;

    auto alice_id = id_seed(0xa1);
    auto bob_id   = id_seed(0xb2);
    auto chan_id  = id_seed(0x42);

    std::vector<std::uint8_t> add_welcome;
    std::int64_t alice_next_seq = 0;

    // ---- Live phase ----
    {
        auto alice_store = fb::store::SqliteStore::open(alice_path);
        auto bob_store   = fb::store::SqliteStore::open(bob_path);

        auto alice = fb::crypto::MlsGroup::create(
            std::span<const std::uint8_t, 32>(alice_id),
            std::span<const std::uint8_t, 32>(chan_id));
        persist_seed(*alice_store, chan_id, *alice);

        auto bob_join = fb::crypto::MlsGroup::start_join(
            std::span<const std::uint8_t, 32>(bob_id));
        auto bob_kp = bob_join->key_package();
        auto add = alice->add_member(as_span(bob_kp));
        alice_next_seq = persist_all_ops(*alice_store, chan_id, *alice,
                                          alice_next_seq);
        add_welcome = std::move(add.welcome);

        auto bob = bob_join->complete(as_span(add_welcome));
        // Joiner-seed persistence: bob saves his seed AFTER complete.
        persist_seed(*bob_store, chan_id, *bob);

        // Sanity: live state works.
        const std::string ping = "alice → bob, before restart";
        std::vector<std::uint8_t> ping_pt(ping.begin(), ping.end());
        auto ping_ct = alice->application_encrypt(as_span(ping_pt));
        auto ping_rx = bob->application_decrypt(as_span(ping_ct));
        ASSERT_TRUE(ping_rx.has_value());
    }
    // ---- All groups dropped. Reopen both DBs, restore, exchange. ----
    {
        auto alice_store = fb::store::SqliteStore::open(alice_path);
        auto bob_store   = fb::store::SqliteStore::open(bob_path);

        auto a_snap = alice_store->mls_group_load(
            std::span<const std::uint8_t>(chan_id.data(), 32));
        auto b_snap = bob_store->mls_group_load(
            std::span<const std::uint8_t>(chan_id.data(), 32));
        ASSERT_TRUE(a_snap.has_value());
        ASSERT_TRUE(b_snap.has_value());
        EXPECT_EQ(a_snap->ops.size(), 1u);   // one Add commit
        EXPECT_EQ(b_snap->ops.size(), 0u);   // joined post-Welcome

        auto alice = fb::crypto::MlsGroup::from_seed_and_log(
            as_span(a_snap->seed), a_snap->ops);
        auto bob = fb::crypto::MlsGroup::from_seed_and_log(
            as_span(b_snap->seed), b_snap->ops);
        ASSERT_NE(alice, nullptr);
        ASSERT_NE(bob, nullptr);
        EXPECT_EQ(alice->member_count(), 2u);
        EXPECT_EQ(bob->member_count(),   2u);

        // alice → bob across restart
        const std::string a_text = "alice from a fresh process";
        std::vector<std::uint8_t> a_pt(a_text.begin(), a_text.end());
        auto a_ct = alice->application_encrypt(as_span(a_pt));
        auto a_rx = bob->application_decrypt(as_span(a_ct));
        ASSERT_TRUE(a_rx.has_value());
        EXPECT_EQ(*a_rx, a_pt);

        // bob → alice across restart
        const std::string b_text = "bob also new pid, same group";
        std::vector<std::uint8_t> b_pt(b_text.begin(), b_text.end());
        auto b_ct = bob->application_encrypt(as_span(b_pt));
        auto b_rx = alice->application_decrypt(as_span(b_ct));
        ASSERT_TRUE(b_rx.has_value());
        EXPECT_EQ(*b_rx, b_pt);
    }
    ::unlink(bob_path.c_str());
}

#endif  // FB_HAVE_MLS
