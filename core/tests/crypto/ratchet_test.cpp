// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// Double Ratchet behavioural tests.
//
// We don't have published byte-for-byte vectors that match our specific KDF
// labels ("FinBit-RK"), so these tests exercise the protocol invariants:
//   - in-order ping-pong succeeds
//   - repeated sends in one direction succeed (symmetric chain)
//   - DH ratchet kicks in on each direction-change
//   - out-of-order delivery up to MAX_SKIP succeeds
//   - replay of a successfully-decrypted message is rejected
//   - tampered AAD or ciphertext is rejected
//   - distinct sessions don't accept each other's traffic
// Cross-vector tests against libsignal-protocol-c are queued for Phase 1.
// =============================================================================

#include "fb/crypto/ratchet.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

struct Pair {
    fb::crypto::DoubleRatchet alice;
    fb::crypto::DoubleRatchet bob;
};

// Build an Alice/Bob pair sharing a deterministic secret + Bob's deterministic
// signed-prekey. Tests use Sodium so sodium_init is implicitly invoked.
Pair make_pair() {
    std::array<std::uint8_t, 32> shared_secret{};
    for (std::size_t i = 0; i < shared_secret.size(); ++i) {
        shared_secret[i] = static_cast<std::uint8_t>(0xA5 ^ i);
    }
    std::array<std::uint8_t, 32> bob_priv{};
    randombytes_buf(bob_priv.data(), bob_priv.size());
    std::array<std::uint8_t, 32> bob_pub{};
    if (crypto_scalarmult_base(bob_pub.data(), bob_priv.data()) != 0) {
        throw std::runtime_error("kp gen");
    }
    return Pair{fb::crypto::DoubleRatchet::init_alice(shared_secret, bob_pub),
                fb::crypto::DoubleRatchet::init_bob(shared_secret, bob_priv, bob_pub)};
}

std::vector<std::uint8_t> bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::span<const std::uint8_t> span_of(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

const std::vector<std::uint8_t> kAad = bytes("envelope-aad-v1");

}  // namespace

TEST(Ratchet, PingPongInOrder) {
    auto p = make_pair();
    const auto m1 = bytes("hi bob");
    const auto m2 = bytes("hi alice");
    const auto m3 = bytes("how are you");

    auto e1 = p.alice.encrypt(span_of(m1), span_of(kAad));
    auto d1 = p.bob.decrypt(span_of(e1), span_of(kAad));
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, m1);

    auto e2 = p.bob.encrypt(span_of(m2), span_of(kAad));
    auto d2 = p.alice.decrypt(span_of(e2), span_of(kAad));
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, m2);

    auto e3 = p.alice.encrypt(span_of(m3), span_of(kAad));
    auto d3 = p.bob.decrypt(span_of(e3), span_of(kAad));
    ASSERT_TRUE(d3.has_value());
    EXPECT_EQ(*d3, m3);
}

TEST(Ratchet, ManyConsecutiveSendsSymmetricChain) {
    auto p = make_pair();
    constexpr int kN = 50;
    std::vector<std::vector<std::uint8_t>> ciphertexts;
    ciphertexts.reserve(kN);
    for (int i = 0; i < kN; ++i) {
        auto m = bytes("msg #" + std::to_string(i));
        ciphertexts.push_back(p.alice.encrypt(span_of(m), span_of(kAad)));
    }
    for (int i = 0; i < kN; ++i) {
        auto d = p.bob.decrypt(span_of(ciphertexts[i]), span_of(kAad));
        ASSERT_TRUE(d.has_value()) << "decrypt failed at i=" << i;
        EXPECT_EQ(std::string(d->begin(), d->end()), "msg #" + std::to_string(i));
    }
}

TEST(Ratchet, OutOfOrderDeliveryWithinMaxSkip) {
    auto p = make_pair();
    auto e0 = p.alice.encrypt(bytes("a"), span_of(kAad));
    auto e1 = p.alice.encrypt(bytes("b"), span_of(kAad));
    auto e2 = p.alice.encrypt(bytes("c"), span_of(kAad));

    // Deliver out of order: 2, 0, 1
    auto d2 = p.bob.decrypt(span_of(e2), span_of(kAad));
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(std::string(d2->begin(), d2->end()), "c");

    auto d0 = p.bob.decrypt(span_of(e0), span_of(kAad));
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(std::string(d0->begin(), d0->end()), "a");

    auto d1 = p.bob.decrypt(span_of(e1), span_of(kAad));
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(std::string(d1->begin(), d1->end()), "b");
}

TEST(Ratchet, ReplayIsRejected) {
    auto p = make_pair();
    auto e = p.alice.encrypt(bytes("once"), span_of(kAad));
    ASSERT_TRUE(p.bob.decrypt(span_of(e), span_of(kAad)).has_value());
    // Same ciphertext again — the message key has been consumed.
    EXPECT_FALSE(p.bob.decrypt(span_of(e), span_of(kAad)).has_value());
}

TEST(Ratchet, TamperedAadRejected) {
    auto p = make_pair();
    auto e = p.alice.encrypt(bytes("hi"), span_of(kAad));
    auto bad_aad = kAad;
    bad_aad[0] ^= 0xff;
    EXPECT_FALSE(p.bob.decrypt(span_of(e), span_of(bad_aad)).has_value());
}

TEST(Ratchet, TamperedCiphertextRejected) {
    auto p = make_pair();
    auto e = p.alice.encrypt(bytes("hi"), span_of(kAad));
    // Flip a byte well inside the protobuf — likely lands in the ciphertext field.
    e.back() ^= 0x01;
    EXPECT_FALSE(p.bob.decrypt(span_of(e), span_of(kAad)).has_value());
}

TEST(Ratchet, DistinctSessionsDoNotAcceptEachOthersTraffic) {
    auto p1 = make_pair();
    auto p2 = make_pair();
    auto e = p1.alice.encrypt(bytes("for p1.bob"), span_of(kAad));
    EXPECT_FALSE(p2.bob.decrypt(span_of(e), span_of(kAad)).has_value());
}

TEST(Ratchet, BobCannotSendBeforeReceiving) {
    auto p = make_pair();
    EXPECT_THROW({ (void)p.bob.encrypt(bytes("nope"), span_of(kAad)); }, std::logic_error);
}

TEST(Ratchet, AlternatingDirectionsAreFineAfterMultipleDhRatchets) {
    auto p = make_pair();
    for (int round = 0; round < 8; ++round) {
        auto a = bytes("alice round " + std::to_string(round));
        auto ea = p.alice.encrypt(span_of(a), span_of(kAad));
        auto da = p.bob.decrypt(span_of(ea), span_of(kAad));
        ASSERT_TRUE(da.has_value()) << "alice->bob failed at round " << round;
        EXPECT_EQ(*da, a);

        auto b = bytes("bob round " + std::to_string(round));
        auto eb = p.bob.encrypt(span_of(b), span_of(kAad));
        auto db = p.alice.decrypt(span_of(eb), span_of(kAad));
        ASSERT_TRUE(db.has_value()) << "bob->alice failed at round " << round;
        EXPECT_EQ(*db, b);
    }
}
