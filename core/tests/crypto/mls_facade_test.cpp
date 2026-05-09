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
