// SPDX-License-Identifier: AGPL-3.0-or-later
// Behavioural tests for SenderKeys group encryption.
//
// We don't have published byte-for-byte vectors for our specific KDF labels
// (kInfoMk = 0x10, kInfoCk = 0x11), so these tests exercise the protocol
// invariants:
//   - one sender, multiple receivers all decrypt identically
//   - out-of-order delivery within MAX_SKIP works
//   - replay rejected (each (chain_id, index) decrypts at most once)
//   - removed peers can't decrypt subsequent messages from a re-keyed sender
//   - distribution-mismatch (post-rekey) triggers nullopt rather than wrong
//     plaintext

#include "fb/crypto/sender_keys.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
std::span<const std::uint8_t> span_of(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

}  // namespace

TEST(SenderKeys, OneSenderTwoReceiversInOrder) {
    fb::crypto::GroupSession alice, bob, carol;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice-pub");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));
    carol.install_peer_distribution(span_of(alice_id), span_of(dist));

    const auto m1 = bytes("hi everyone");
    auto e1 = alice.encrypt(span_of(m1), {});
    auto db = bob.decrypt(span_of(alice_id), span_of(e1), {});
    auto dc = carol.decrypt(span_of(alice_id), span_of(e1), {});
    ASSERT_TRUE(db.has_value());
    ASSERT_TRUE(dc.has_value());
    EXPECT_EQ(*db, m1);
    EXPECT_EQ(*dc, m1);

    const auto m2 = bytes("more");
    auto e2 = alice.encrypt(span_of(m2), {});
    EXPECT_EQ(*bob.decrypt(span_of(alice_id), span_of(e2), {}), m2);
    EXPECT_EQ(*carol.decrypt(span_of(alice_id), span_of(e2), {}), m2);
}

TEST(SenderKeys, OutOfOrderWithinMaxSkip) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));

    auto e0 = alice.encrypt(bytes("zero"), {});
    auto e1 = alice.encrypt(bytes("one"), {});
    auto e2 = alice.encrypt(bytes("two"), {});

    // Deliver 2, 0, 1.
    auto d2 = bob.decrypt(span_of(alice_id), span_of(e2), {});
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(std::string(d2->begin(), d2->end()), "two");

    auto d0 = bob.decrypt(span_of(alice_id), span_of(e0), {});
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(std::string(d0->begin(), d0->end()), "zero");

    auto d1 = bob.decrypt(span_of(alice_id), span_of(e1), {});
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(std::string(d1->begin(), d1->end()), "one");
}

TEST(SenderKeys, ReplayRejected) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));

    auto e = alice.encrypt(bytes("once"), {});
    EXPECT_TRUE(bob.decrypt(span_of(alice_id), span_of(e), {}).has_value());
    EXPECT_FALSE(bob.decrypt(span_of(alice_id), span_of(e), {}).has_value());
}

TEST(SenderKeys, EncryptBeforeDistributionThrows) {
    fb::crypto::GroupSession alice;
    EXPECT_THROW({ (void)alice.encrypt(bytes("x"), {}); }, std::logic_error);
}

TEST(SenderKeys, UnknownSenderReturnsNullopt) {
    fb::crypto::GroupSession bob;
    fb::crypto::GroupSession alice;
    (void)alice.create_own_send_chain();  // distribution not given to bob
    auto e = alice.encrypt(bytes("hi"), {});
    EXPECT_FALSE(bob.decrypt(span_of(bytes("alice")), span_of(e), {}).has_value());
}

TEST(SenderKeys, RemovePeerStopsDecryption) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));
    auto e1 = alice.encrypt(bytes("before"), {});
    EXPECT_TRUE(bob.decrypt(span_of(alice_id), span_of(e1), {}).has_value());
    bob.remove_peer(span_of(alice_id));
    auto e2 = alice.encrypt(bytes("after"), {});
    EXPECT_FALSE(bob.decrypt(span_of(alice_id), span_of(e2), {}).has_value());
}

// Post-eviction key isolation: after a member is removed and the
// remaining members re-key, the evicted member CANNOT decrypt new
// channel traffic. This is the property that makes channel removal
// meaningful — the evicted member kept their old chain key state in
// memory, but the new distribution gives them no way to derive
// future message keys.
//
// Scenario:
//   1. Alice creates a send chain v1; Bob and Carol install it.
//   2. Carol is evicted (e.g. kicked from the channel).
//   3. Alice re-keys: create_own_send_chain() produces chain v2.
//   4. Bob installs the new distribution and decrypts v2 traffic.
//   5. Carol, holding the old v1 distribution, MUST NOT decrypt v2
//      traffic — the chain_id mismatch rejection in
//      RekeyingProducesNewChainId is precisely the defense, but
//      this test asserts it specifically in the post-eviction
//      threat model.
TEST(SenderKeys, EvictedMemberCannotDecryptPostRekeyTraffic) {
    fb::crypto::GroupSession alice, bob, carol;
    const auto alice_id = bytes("alice");

    // v1 — all three start with the same distribution.
    auto dist_v1 = alice.create_own_send_chain();
    bob.install_peer_distribution(span_of(alice_id), span_of(dist_v1));
    carol.install_peer_distribution(span_of(alice_id), span_of(dist_v1));

    auto pre = alice.encrypt(bytes("pre-eviction-msg"), {});
    EXPECT_TRUE(bob.decrypt(span_of(alice_id), span_of(pre), {}).has_value());
    EXPECT_TRUE(carol.decrypt(span_of(alice_id), span_of(pre), {}).has_value());

    // Evict carol (no API on alice's side — eviction is a higher-layer
    // decision; the crypto effect is that alice re-keys, generating a
    // new distribution which is delivered ONLY to bob).
    auto dist_v2 = alice.create_own_send_chain();
    bob.install_peer_distribution(span_of(alice_id), span_of(dist_v2));
    // carol does NOT receive dist_v2.

    // Alice sends a post-eviction message under v2.
    auto post = alice.encrypt(bytes("post-eviction-secret"), {});

    // Bob can read it — he has v2.
    auto bob_pt = bob.decrypt(span_of(alice_id), span_of(post), {});
    ASSERT_TRUE(bob_pt.has_value());
    EXPECT_EQ(std::string(bob_pt->begin(), bob_pt->end()),
              "post-eviction-secret");

    // Carol CANNOT — she's still on v1; chain_id mismatch.
    auto carol_pt = carol.decrypt(span_of(alice_id), span_of(post), {});
    EXPECT_FALSE(carol_pt.has_value())
        << "evicted member decrypted post-rekey traffic — channel eviction "
           "is broken (post-compromise security gap)";

    // Even if alice sends MANY more messages on v2, carol stays locked out.
    for (int i = 0; i < 5; ++i) {
        auto e = alice.encrypt(bytes("msg-" + std::to_string(i)), {});
        EXPECT_TRUE(bob.decrypt(span_of(alice_id), span_of(e), {}).has_value());
        EXPECT_FALSE(carol.decrypt(span_of(alice_id), span_of(e), {}).has_value());
    }
}

TEST(SenderKeys, RekeyingProducesNewChainId) {
    fb::crypto::GroupSession alice, bob;
    auto dist1 = alice.create_own_send_chain();
    auto dist2 = alice.create_own_send_chain();
    EXPECT_NE(dist1, dist2);  // re-key produces a new distribution
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist1));
    auto e_after = alice.encrypt(bytes("after-rekey"), {});
    // bob still on dist1; e_after is encrypted under dist2 (alice's current chain).
    // chain_id mismatch — must reject rather than silently produce wrong
    // plaintext.
    EXPECT_FALSE(bob.decrypt(span_of(alice_id), span_of(e_after), {}).has_value());
    // After bob receives the new distribution he can catch up.
    bob.install_peer_distribution(span_of(alice_id), span_of(dist2));
    auto recovered = bob.decrypt(span_of(alice_id), span_of(e_after), {});
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(std::string(recovered->begin(), recovered->end()), "after-rekey");
}

TEST(SenderKeys, SerializeDeserializeRoundTripPreservesSendChainAndPeers) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));

    // Send + receive a couple so the chain has advanced.
    auto e0 = alice.encrypt(bytes("first"), {});
    auto d0 = bob.decrypt(span_of(alice_id), span_of(e0), {});
    ASSERT_TRUE(d0.has_value());
    auto e1 = alice.encrypt(bytes("second"), {});

    // Snapshot bob, throw the original away, reload from the blob.
    auto bob_blob = bob.serialize_state();
    auto reloaded = fb::crypto::GroupSession::deserialize_state(span_of(bob_blob));
    ASSERT_NE(reloaded, nullptr);

    // The reloaded bob can decrypt the next-in-order message from alice.
    auto d1 = reloaded->decrypt(span_of(alice_id), span_of(e1), {});
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(std::string(d1->begin(), d1->end()), "second");

    // And alice's chain reloads too — she can keep sending from where she left off.
    auto alice_blob = alice.serialize_state();
    auto alice_reloaded = fb::crypto::GroupSession::deserialize_state(span_of(alice_blob));
    ASSERT_NE(alice_reloaded, nullptr);
    auto e2 = alice_reloaded->encrypt(bytes("third"), {});
    auto d2 = reloaded->decrypt(span_of(alice_id), span_of(e2), {});
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(std::string(d2->begin(), d2->end()), "third");
}

TEST(SenderKeys, DeserializeRejectsMalformedBlobs) {
    EXPECT_EQ(fb::crypto::GroupSession::deserialize_state({}), nullptr);
    auto garbage = bytes("not a serialized state");
    EXPECT_EQ(fb::crypto::GroupSession::deserialize_state(span_of(garbage)), nullptr);
}

// Regression: a forged ciphertext at the receiver's CURRENT chain index
// must not advance the chain. Previously the chain ratcheted before AEAD
// verification, so a single failed decrypt permanently desynced the
// receiver from the sender's next legit message.
TEST(SenderKeys, ForgedMessageDoesNotDesyncChain) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));
    // Alice produces messages 0 and 1 — bob will only see 1 (after the forge).
    auto ct0 = alice.encrypt(bytes("first"),  {});
    auto ct1 = alice.encrypt(bytes("second"), {});
    // Forge: take ct0 and flip a bit in its ciphertext. This still has a
    // valid SenderKeysMessage proto envelope (chain_id, index=0), so it
    // reaches the AEAD step at the receiver's current chain position.
    auto forged = ct0;
    forged.back() ^= 0x01;
    EXPECT_FALSE(bob.decrypt(span_of(alice_id), span_of(forged), {}).has_value());
    // The legitimate ct0 must still decrypt — chain didn't advance.
    auto d0 = bob.decrypt(span_of(alice_id), span_of(ct0), {});
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(std::string(d0->begin(), d0->end()), "first");
    // And ct1 follows naturally.
    auto d1 = bob.decrypt(span_of(alice_id), span_of(ct1), {});
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(std::string(d1->begin(), d1->end()), "second");
}

// Regression: same property for the SKIPPED-cache path. A forged message
// at an index in the skipped cache must not erase the cached key — the
// legitimate message at that index must still decrypt on arrival.
TEST(SenderKeys, ForgedSkippedMessageLeavesCacheIntact) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));
    auto ct0 = alice.encrypt(bytes("zero"), {});
    auto ct1 = alice.encrypt(bytes("one"),  {});
    auto ct2 = alice.encrypt(bytes("two"),  {});
    // Bob receives ct2 first → keys for indices 0 and 1 land in skipped cache.
    auto d2 = bob.decrypt(span_of(alice_id), span_of(ct2), {});
    ASSERT_TRUE(d2.has_value());
    // Forge a bit-flipped ct1.
    auto forged = ct1;
    forged.back() ^= 0x01;
    EXPECT_FALSE(bob.decrypt(span_of(alice_id), span_of(forged), {}).has_value());
    // Legitimate ct1 must still decrypt from the skipped cache.
    auto d1 = bob.decrypt(span_of(alice_id), span_of(ct1), {});
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(std::string(d1->begin(), d1->end()), "one");
    auto d0 = bob.decrypt(span_of(alice_id), span_of(ct0), {});
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(std::string(d0->begin(), d0->end()), "zero");
}

TEST(SenderKeys, ManyMessagesSymmetricChain) {
    fb::crypto::GroupSession alice, bob;
    auto dist = alice.create_own_send_chain();
    const auto alice_id = bytes("alice");
    bob.install_peer_distribution(span_of(alice_id), span_of(dist));
    constexpr int kN = 100;
    std::vector<std::vector<std::uint8_t>> cts;
    cts.reserve(kN);
    for (int i = 0; i < kN; ++i) {
        cts.push_back(alice.encrypt(bytes("m" + std::to_string(i)), {}));
    }
    for (int i = 0; i < kN; ++i) {
        auto d = bob.decrypt(span_of(alice_id), span_of(cts[i]), {});
        ASSERT_TRUE(d.has_value()) << "decrypt failed at i=" << i;
        EXPECT_EQ(std::string(d->begin(), d->end()), "m" + std::to_string(i));
    }
}
