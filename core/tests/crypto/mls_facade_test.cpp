// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// MlsGroup wrapper smoke tests.
//
// FB_HAVE_MLS=0 build: every method MUST throw "not implemented" — proves
// the off-by-default code path is wired.
//
// FB_HAVE_MLS=1 build: a single-member group can encrypt + decrypt its own
// application messages — proves the mlspp link works end-to-end and the
// PIMPL routes calls through to mls::Session correctly.
//
// Multi-member welcome / commit / remove tests are deferred to a follow-up
// once MlsGroup::add_member is paired with a complete Welcome-application
// flow on the receiver side (the public facade only exposes the producer
// half today; the join-from-Welcome path needs an MlsGroup::join_from_
// welcome() entry point that doesn't exist yet).
// =============================================================================

#include "fb/crypto/mls_facade.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

std::array<std::uint8_t, 32> seed(std::uint8_t fill) {
    std::array<std::uint8_t, 32> out{};
    for (auto& b : out) b = fill;
    return out;
}

}  // namespace

#if FB_HAVE_MLS

TEST(MlsFacade, SingleMemberRoundTrip) {
    auto identity = seed(0xa1);
    auto group_id = seed(0x42);
    auto g = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(identity),
        std::span<const std::uint8_t, 32>(group_id));
    ASSERT_NE(g, nullptr);
    EXPECT_EQ(g->member_count(), 1u);

    const std::string pt_text = "hello mls world";
    std::vector<std::uint8_t> pt(pt_text.begin(), pt_text.end());
    auto ct = g->application_encrypt(
        std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_FALSE(ct.empty());
    // mls::Session.protect produces an MLSMessage that's strictly larger
    // than the plaintext (header + tag); it should NOT contain the
    // plaintext verbatim.
    auto blob = std::string_view(reinterpret_cast<const char*>(ct.data()),
                                  ct.size());
    EXPECT_EQ(blob.find(pt_text), std::string_view::npos)
        << "MLSMessage contained plaintext bytes — encryption is broken";

    auto round = g->application_decrypt(
        std::span<const std::uint8_t>(ct.data(), ct.size()));
    ASSERT_TRUE(round.has_value());
    EXPECT_EQ(*round, pt);
}

TEST(MlsFacade, ApplicationDecryptOfGarbageReturnsNullopt) {
    auto identity = seed(0xa1);
    auto group_id = seed(0x42);
    auto g = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(identity),
        std::span<const std::uint8_t, 32>(group_id));
    std::vector<std::uint8_t> junk{1, 2, 3, 4, 5, 6, 7, 8};
    auto out = g->application_decrypt(
        std::span<const std::uint8_t>(junk.data(), junk.size()));
    EXPECT_FALSE(out.has_value());
}

// Two-member round trip exercising the full add_member → Welcome →
// complete flow: alice creates the group, bob publishes a KeyPackage,
// alice add_member's bob (producing Welcome+Commit), bob complete()s
// the Welcome to get his own MlsGroup, then both directions encrypt
// + decrypt application messages.
TEST(MlsFacade, TwoMemberAddJoinRoundTrip) {
    auto alice_id = seed(0xa1);
    auto bob_id   = seed(0xb2);
    auto group_id = seed(0x42);

    // 1. Alice creates the group.
    auto alice = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(group_id));
    ASSERT_NE(alice, nullptr);
    EXPECT_EQ(alice->member_count(), 1u);

    // 2. Bob starts a pending join, publishes his KeyPackage.
    auto bob_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    ASSERT_NE(bob_join, nullptr);
    auto kp = bob_join->key_package();
    EXPECT_FALSE(kp.empty());

    // 3. Alice adds Bob via his KP — produces a Welcome (for Bob) and a
    //    Commit (for the existing roster, which is just Alice today).
    auto add = alice->add_member(
        std::span<const std::uint8_t>(kp.data(), kp.size()));
    EXPECT_FALSE(add.welcome.empty());
    EXPECT_FALSE(add.commit.empty());
    EXPECT_EQ(alice->member_count(), 2u);

    // 4. Bob completes his pending join with the Welcome — yields a
    //    hydrated MlsGroup that shares the new epoch with Alice.
    auto bob = bob_join->complete(
        std::span<const std::uint8_t>(add.welcome.data(), add.welcome.size()));
    ASSERT_NE(bob, nullptr);
    EXPECT_EQ(bob->member_count(), 2u);

    // 5. Alice → Bob: encrypt under Alice's session, decrypt under
    //    Bob's. Different processes, same MLS group state.
    const std::string a_text = "alice to bob over mls";
    std::vector<std::uint8_t> a_pt(a_text.begin(), a_text.end());
    auto a_ct = alice->application_encrypt(
        std::span<const std::uint8_t>(a_pt.data(), a_pt.size()));
    auto a_round = bob->application_decrypt(
        std::span<const std::uint8_t>(a_ct.data(), a_ct.size()));
    ASSERT_TRUE(a_round.has_value());
    EXPECT_EQ(*a_round, a_pt);

    // 6. Bob → Alice the other direction.
    const std::string b_text = "bob replying";
    std::vector<std::uint8_t> b_pt(b_text.begin(), b_text.end());
    auto b_ct = bob->application_encrypt(
        std::span<const std::uint8_t>(b_pt.data(), b_pt.size()));
    auto b_round = alice->application_decrypt(
        std::span<const std::uint8_t>(b_ct.data(), b_ct.size()));
    ASSERT_TRUE(b_round.has_value());
    EXPECT_EQ(*b_round, b_pt);
}

// Three members exercising member_identities() + a real Commit
// broadcast: alice creates, adds bob, then adds carol. Carol must be
// hydrated with the welcome from alice's add(carol). Bob must apply
// the commit alice produced for the carol-add or he'll be stuck at
// the previous epoch and decrypt of carol's first message will fail.
TEST(MlsFacade, ThreeMemberMembershipAndCommitFanout) {
    auto alice_id = seed(0xa1);
    auto bob_id   = seed(0xb2);
    auto carol_id = seed(0xc3);
    auto group_id = seed(0x42);

    auto alice = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(group_id));

    // Add bob.
    auto bob_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    auto bob_kp = bob_join->key_package();
    auto bob_add = alice->add_member(
        std::span<const std::uint8_t>(bob_kp.data(), bob_kp.size()));
    auto bob = bob_join->complete(
        std::span<const std::uint8_t>(bob_add.welcome.data(),
                                       bob_add.welcome.size()));

    // Add carol — multi-member path. alice propose_add's,
    // broadcasts the proposal to bob (who handle_proposal's it to
    // stage locally), then alice commit_pending's. The Commit
    // alice produces is now applicable by bob too because bob has
    // the staged proposal in his local state. This matches the
    // canonical MLS 2-broadcast flow shown in mlspp's
    // test/session.cpp::broadcast_add().
    auto carol_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(carol_id));
    auto carol_kp = carol_join->key_package();

    auto proposal = alice->propose_add_member(
        std::span<const std::uint8_t>(carol_kp.data(), carol_kp.size()));
    bob->handle_proposal(
        std::span<const std::uint8_t>(proposal.data(), proposal.size()));

    auto carol_add = alice->commit_pending();
    auto carol = carol_join->complete(
        std::span<const std::uint8_t>(carol_add.welcome.data(),
                                       carol_add.welcome.size()));
    bob->apply_commit(std::span<const std::uint8_t>(
        carol_add.commit.data(), carol_add.commit.size()));

    // member_identities() returns each member's BasicCredential identity
    // bytes; this is what ChatClient uses to fan out commits.
    EXPECT_EQ(alice->member_count(), 3u);
    EXPECT_EQ(bob->member_count(),   3u);
    EXPECT_EQ(carol->member_count(), 3u);

    auto find_identity = [](const fb::crypto::MlsGroup& g, std::uint8_t fill) {
        std::vector<std::uint8_t> wanted(32, fill);
        for (const auto& id : g.member_identities()) {
            if (id == wanted) return true;
        }
        return false;
    };
    for (auto* g : {alice.get(), bob.get(), carol.get()}) {
        EXPECT_TRUE(find_identity(*g, 0xa1));
        EXPECT_TRUE(find_identity(*g, 0xb2));
        EXPECT_TRUE(find_identity(*g, 0xc3));
    }

    // Cross-direction round trips at the new (3-member) epoch.
    const std::string m_text = "carol to the room";
    std::vector<std::uint8_t> m_pt(m_text.begin(), m_text.end());
    auto m_ct = carol->application_encrypt(
        std::span<const std::uint8_t>(m_pt.data(), m_pt.size()));
    auto a_round = alice->application_decrypt(
        std::span<const std::uint8_t>(m_ct.data(), m_ct.size()));
    auto b_round = bob->application_decrypt(
        std::span<const std::uint8_t>(m_ct.data(), m_ct.size()));
    ASSERT_TRUE(a_round.has_value());
    ASSERT_TRUE(b_round.has_value());
    EXPECT_EQ(*a_round, m_pt);
    EXPECT_EQ(*b_round, m_pt);
}

// ---------------------------------------------------------------------------
// Persistence round trips. Two scenarios that each restore via the
// transcript-replay layer (seed + commit log → from_seed_and_log)
// and prove the rebuilt State decrypts MLS application traffic that
// was encrypted by the live State.
// ---------------------------------------------------------------------------

// Diagnostic: serialize twice in a row from the same live group;
// the seeds MUST be byte-identical or the persistence layer is
// non-deterministic and any creator-seed restore is doomed.
TEST(MlsFacade, CreatorSeedIsIdempotent) {
    auto identity = seed(0xa1);
    auto group_id = seed(0x42);
    auto live = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(identity),
        std::span<const std::uint8_t, 32>(group_id));
    auto s1 = live->serialize_seed();
    auto s2 = live->serialize_seed();
    EXPECT_EQ(s1, s2);
}

// Single-member creator: serialize → from_blob → encrypt with the
// rebuilt group → decrypt with the rebuilt group. No commits in the
// log; verifies the seed alone is sufficient to rebuild a fresh
// (epoch=0) State.
TEST(MlsFacade, CreatorPersistenceRoundTripNoCommits) {
    auto identity = seed(0xa1);
    auto group_id = seed(0x42);
    auto live = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(identity),
        std::span<const std::uint8_t, 32>(group_id));

    auto blob = live->serialize();
    EXPECT_FALSE(blob.empty());
    EXPECT_TRUE(live->operation_log().empty());

    auto restored = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(blob.data(), blob.size()));
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->member_count(), 1u);

    // Encrypt under the restored group, decrypt under a SECOND
    // restoration from the same blob — proves the seed is the only
    // input needed to reach an identical State.
    auto restored2 = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(blob.data(), blob.size()));
    const std::string text = "after restart, before any peers";
    std::vector<std::uint8_t> pt(text.begin(), text.end());
    auto ct = restored->application_encrypt(
        std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto round = restored2->application_decrypt(
        std::span<const std::uint8_t>(ct.data(), ct.size()));
    ASSERT_TRUE(round.has_value());
    EXPECT_EQ(*round, pt);
}

// Two members + one Add commit in the log: alice creates, adds bob,
// then both alice and bob serialize. Both restore independently
// (alice via creator-seed + 1 commit replay; bob via joiner-seed +
// 0 commits since bob's seed was captured at Welcome-complete which
// is already epoch=1). After restore the two groups must share the
// same epoch and decrypt each other's application messages.
TEST(MlsFacade, JoinerPersistenceRoundTripAcrossWelcome) {
    auto alice_id = seed(0xa1);
    auto bob_id   = seed(0xb2);
    auto group_id = seed(0x42);

    auto alice_live = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(group_id));
    auto bob_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    auto bob_kp = bob_join->key_package();
    auto add = alice_live->add_member(
        std::span<const std::uint8_t>(bob_kp.data(), bob_kp.size()));
    auto bob_live = bob_join->complete(
        std::span<const std::uint8_t>(add.welcome.data(), add.welcome.size()));
    EXPECT_EQ(alice_live->member_count(), 2u);
    EXPECT_EQ(bob_live->member_count(),   2u);

    auto alice_blob = alice_live->serialize();
    auto bob_blob   = bob_live->serialize();

    // Drop the live groups to make sure restore really stands alone.
    alice_live.reset();
    bob_live.reset();

    auto alice_restored = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(alice_blob.data(), alice_blob.size()));
    auto bob_restored = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(bob_blob.data(), bob_blob.size()));
    ASSERT_NE(alice_restored, nullptr);
    ASSERT_NE(bob_restored, nullptr);
    EXPECT_EQ(alice_restored->member_count(), 2u);
    EXPECT_EQ(bob_restored->member_count(),   2u);

    // Cross-direction round trip across the simulated restart: alice
    // → bob and bob → alice both at the same epoch.
    const std::string a_text = "alice after restart";
    std::vector<std::uint8_t> a_pt(a_text.begin(), a_text.end());
    auto a_ct = alice_restored->application_encrypt(
        std::span<const std::uint8_t>(a_pt.data(), a_pt.size()));
    auto a_round = bob_restored->application_decrypt(
        std::span<const std::uint8_t>(a_ct.data(), a_ct.size()));
    ASSERT_TRUE(a_round.has_value());
    EXPECT_EQ(*a_round, a_pt);

    const std::string b_text = "bob after restart";
    std::vector<std::uint8_t> b_pt(b_text.begin(), b_text.end());
    auto b_ct = bob_restored->application_encrypt(
        std::span<const std::uint8_t>(b_pt.data(), b_pt.size()));
    auto b_round = alice_restored->application_decrypt(
        std::span<const std::uint8_t>(b_ct.data(), b_ct.size()));
    ASSERT_TRUE(b_round.has_value());
    EXPECT_EQ(*b_round, b_pt);
}

// Three members with a multi-Commit transcript. After bob joins
// (1 commit), alice adds carol via the broadcast pattern (1 more
// commit applied to alice and bob; carol gets the Welcome). All
// three serialize. After dropping all live groups, all three
// restore from their own seeds + their own commit logs. The
// restored alice/bob/carol must all reach the same epoch and decrypt
// a fresh message produced by any of them.
//
// This is the load-bearing test: it proves the transcript-replay
// loop in from_seed_and_log actually produces the right epoch,
// not just an epoch that looks plausible.
TEST(MlsFacade, MultiCommitTranscriptReplayThreeMembers) {
    auto alice_id = seed(0xa1);
    auto bob_id   = seed(0xb2);
    auto carol_id = seed(0xc3);
    auto group_id = seed(0x42);

    auto alice = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(group_id));

    // Add bob (epoch 0 → 1).
    auto bob_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    auto bob_kp = bob_join->key_package();
    auto bob_add = alice->add_member(
        std::span<const std::uint8_t>(bob_kp.data(), bob_kp.size()));
    auto bob = bob_join->complete(
        std::span<const std::uint8_t>(bob_add.welcome.data(),
                                       bob_add.welcome.size()));

    // Add carol (epoch 1 → 2) via the multi-broadcast path.
    auto carol_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(carol_id));
    auto carol_kp = carol_join->key_package();
    auto proposal = alice->propose_add_member(
        std::span<const std::uint8_t>(carol_kp.data(), carol_kp.size()));
    bob->handle_proposal(
        std::span<const std::uint8_t>(proposal.data(), proposal.size()));
    auto carol_add = alice->commit_pending();
    auto carol = carol_join->complete(
        std::span<const std::uint8_t>(carol_add.welcome.data(),
                                       carol_add.welcome.size()));
    bob->apply_commit(std::span<const std::uint8_t>(
        carol_add.commit.data(), carol_add.commit.size()));

    // Snapshot every node.
    auto alice_blob = alice->serialize();
    auto bob_blob   = bob->serialize();
    auto carol_blob = carol->serialize();

    // operation_log sanity. Operation counts (NOT commit counts —
    // each propose / commit_pending / apply_commit / handle_proposal
    // is its own op):
    //   alice: ADD_MEMBER(bob), PROPOSE_ADD(carol), COMMIT_PENDING = 3
    //   bob:   HANDLE_PROPOSAL(carol),  APPLY_COMMIT(carol_add)    = 2
    //   carol: started post-Welcome, no ops applied yet            = 0
    EXPECT_EQ(alice->operation_log().size(), 3u);
    EXPECT_EQ(bob->operation_log().size(), 2u);
    EXPECT_EQ(carol->operation_log().size(), 0u);

    // Drop live groups; restore from blobs.
    alice.reset(); bob.reset(); carol.reset();

    auto alice2 = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(alice_blob.data(), alice_blob.size()));
    auto bob2 = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(bob_blob.data(), bob_blob.size()));
    auto carol2 = fb::crypto::MlsGroup::from_blob(
        std::span<const std::uint8_t>(carol_blob.data(), carol_blob.size()));

    EXPECT_EQ(alice2->member_count(), 3u);
    EXPECT_EQ(bob2->member_count(),   3u);
    EXPECT_EQ(carol2->member_count(), 3u);

    // 3-way decrypt at the restored epoch.
    const std::string text = "carol speaks after a full-fleet restart";
    std::vector<std::uint8_t> pt(text.begin(), text.end());
    auto ct = carol2->application_encrypt(
        std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto a_round = alice2->application_decrypt(
        std::span<const std::uint8_t>(ct.data(), ct.size()));
    auto b_round = bob2->application_decrypt(
        std::span<const std::uint8_t>(ct.data(), ct.size()));
    ASSERT_TRUE(a_round.has_value());
    ASSERT_TRUE(b_round.has_value());
    EXPECT_EQ(*a_round, pt);
    EXPECT_EQ(*b_round, pt);
}

// Split form (serialize_seed + operation_log separately) round
// trips through from_seed_and_log. This is the form ChatClient
// actually uses against the SQLite store: seed in mls_group_state,
// commits appended one-by-one to mls_group_log.
TEST(MlsFacade, SplitSeedAndLogRoundTrip) {
    auto alice_id = seed(0xa1);
    auto bob_id   = seed(0xb2);
    auto group_id = seed(0x42);

    auto alice = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(group_id));
    auto bob_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    auto bob_kp = bob_join->key_package();
    auto add = alice->add_member(
        std::span<const std::uint8_t>(bob_kp.data(), bob_kp.size()));
    (void)bob_join->complete(
        std::span<const std::uint8_t>(add.welcome.data(), add.welcome.size()));

    auto seed_bytes = alice->serialize_seed();
    auto commits    = alice->operation_log();
    EXPECT_FALSE(seed_bytes.empty());
    EXPECT_EQ(commits.size(), 1u);

    auto alice2 = fb::crypto::MlsGroup::from_seed_and_log(
        std::span<const std::uint8_t>(seed_bytes.data(), seed_bytes.size()),
        commits);
    ASSERT_NE(alice2, nullptr);
    EXPECT_EQ(alice2->member_count(), 2u);

    // Re-add bob from a fresh start_join (his old keys are gone) to
    // prove alice2 is a fully-functional State capable of doing work
    // in the new session, not just an epoch-frozen replica.
    auto bob_rejoin = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    auto bob_kp2 = bob_rejoin->key_package();
    auto add2 = alice2->add_member(
        std::span<const std::uint8_t>(bob_kp2.data(), bob_kp2.size()));
    EXPECT_FALSE(add2.welcome.empty());
    EXPECT_FALSE(add2.commit.empty());
    EXPECT_EQ(alice2->member_count(), 3u);
}

// ---------------------------------------------------------------------------
// MLS exporter → group-call room secret (RFC 9420 §8.5).
//
// This is the MLS-channel source for the SFrame room_secret: instead of
// DMing a RoomKey (the SenderKeys path), every member derives the SAME
// 32 bytes locally from the group's exporter secret — no extra message —
// and it rotates for free on every Commit. The properties that make it a
// valid room_secret source: (1) identical across all members at an epoch,
// (2) deterministic, (3) bound to the channel (group_id context), and
// (4) rotates when membership changes.
// ---------------------------------------------------------------------------
TEST(MlsFacade, RoomSecretExporterAgreesAcrossMembersAndRotates) {
    auto alice_id = seed(0xa1);
    auto bob_id   = seed(0xb2);
    auto carol_id = seed(0xc3);
    auto group_id = seed(0x42);

    // alice + bob synced at a shared epoch (add → Welcome → complete).
    auto alice = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(group_id));
    auto bob_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(bob_id));
    auto bob_kp = bob_join->key_package();
    auto bob_add = alice->add_member(
        std::span<const std::uint8_t>(bob_kp.data(), bob_kp.size()));
    auto bob = bob_join->complete(std::span<const std::uint8_t>(
        bob_add.welcome.data(), bob_add.welcome.size()));

    // (1) Same epoch, (2) byte-identical secret across members.
    EXPECT_EQ(alice->epoch(), bob->epoch());
    auto a_secret = alice->export_room_secret();
    auto b_secret = bob->export_room_secret();
    EXPECT_EQ(a_secret, b_secret);

    // (3) Deterministic: re-derivation yields the same bytes; and it's not
    //     trivially all-zero.
    EXPECT_EQ(a_secret, alice->export_room_secret());
    std::array<std::uint8_t, 32> zero{};
    EXPECT_NE(a_secret, zero);

    // Bound to the channel: a different group_id → a different secret even
    // at the same (epoch-0) membership.
    auto other = fb::crypto::MlsGroup::create(
        std::span<const std::uint8_t, 32>(alice_id),
        std::span<const std::uint8_t, 32>(seed(0x99)));
    EXPECT_NE(other->export_room_secret(), a_secret);

    // (4) Membership change re-keys the room for free: add carol (a Commit),
    //     epoch bumps, secret rotates, and all three still agree.
    const auto epoch_before = alice->epoch();
    auto carol_join = fb::crypto::MlsGroup::start_join(
        std::span<const std::uint8_t, 32>(carol_id));
    auto carol_kp = carol_join->key_package();
    auto proposal = alice->propose_add_member(
        std::span<const std::uint8_t>(carol_kp.data(), carol_kp.size()));
    bob->handle_proposal(
        std::span<const std::uint8_t>(proposal.data(), proposal.size()));
    auto carol_add = alice->commit_pending();
    auto carol = carol_join->complete(std::span<const std::uint8_t>(
        carol_add.welcome.data(), carol_add.welcome.size()));
    bob->apply_commit(std::span<const std::uint8_t>(
        carol_add.commit.data(), carol_add.commit.size()));

    EXPECT_GT(alice->epoch(), epoch_before);          // epoch advanced
    auto a_secret2 = alice->export_room_secret();
    EXPECT_NE(a_secret2, a_secret);                   // rotated
    EXPECT_EQ(a_secret2, bob->export_room_secret());  // still agree …
    EXPECT_EQ(a_secret2, carol->export_room_secret());// … all three
    EXPECT_EQ(alice->epoch(), carol->epoch());
}

#else  // FB_HAVE_MLS == 0

TEST(MlsFacade, StubBuildThrowsNotImplemented) {
    auto identity = seed(0x00);
    auto group_id = seed(0x00);
    EXPECT_THROW({
        (void)fb::crypto::MlsGroup::create(
            std::span<const std::uint8_t, 32>(identity),
            std::span<const std::uint8_t, 32>(group_id));
    }, std::runtime_error);
}

#endif  // FB_HAVE_MLS
