// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/identity.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {
const std::vector<std::uint8_t> kHelloWorld = {'h', 'e', 'l', 'l', 'o'};
}  // namespace

TEST(Identity, GeneratesUniqueIdentities) {
    const auto a = fb::crypto::Identity::generate();
    const auto b = fb::crypto::Identity::generate();
    EXPECT_NE(a.public_key(), b.public_key());
}

TEST(Identity, FromSeedIsDeterministic) {
    std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);
    const auto a = fb::crypto::Identity::from_seed(seed);
    const auto b = fb::crypto::Identity::from_seed(seed);
    EXPECT_EQ(a.public_key(), b.public_key());
    EXPECT_EQ(a.fingerprint(), b.fingerprint());
}

TEST(Identity, SignVerifyRoundTrip) {
    const auto id = fb::crypto::Identity::generate();
    const auto sig = id.sign(kHelloWorld);
    EXPECT_TRUE(fb::crypto::Identity::verify(id.public_key(), kHelloWorld, sig));
}

TEST(Identity, VerifyRejectsTamperedMessage) {
    const auto id = fb::crypto::Identity::generate();
    const auto sig = id.sign(kHelloWorld);
    auto tampered = kHelloWorld;
    tampered[0] ^= 0x01;
    EXPECT_FALSE(fb::crypto::Identity::verify(id.public_key(), tampered, sig));
}

TEST(Identity, VerifyRejectsTamperedSignature) {
    const auto id = fb::crypto::Identity::generate();
    auto sig = id.sign(kHelloWorld);
    sig[0] ^= 0x01;
    EXPECT_FALSE(fb::crypto::Identity::verify(id.public_key(), kHelloWorld, sig));
}

TEST(Identity, FingerprintIsStableAndFormatted) {
    std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed{};
    seed.fill(0x42);
    const auto id = fb::crypto::Identity::from_seed(seed);
    const auto fp = id.fingerprint();
    EXPECT_EQ(fp.size(), 11u);  // XXXXX-XXXXX
    EXPECT_EQ(fp[5], '-');
    // Re-derive and confirm stability.
    EXPECT_EQ(id.fingerprint(), fb::crypto::Identity::fingerprint(id.public_key()));
}

TEST(Identity, PubkeyBase64RoundTrip) {
    const auto id = fb::crypto::Identity::generate();
    const auto encoded = fb::crypto::pubkey_to_base64(id.public_key());
    fb::crypto::PubKey decoded{};
    ASSERT_TRUE(fb::crypto::pubkey_from_base64(encoded, decoded));
    EXPECT_EQ(decoded, id.public_key());
}

// ---- safety_number (MITM-detection — Tier 11) -----------------------------

TEST(Identity, SafetyNumberIsOrderIndependent) {
    auto alice = fb::crypto::Identity::generate();
    auto bob   = fb::crypto::Identity::generate();
    const auto ab = fb::crypto::safety_number(alice.public_key(), bob.public_key());
    const auto ba = fb::crypto::safety_number(bob.public_key(), alice.public_key());
    EXPECT_EQ(ab, ba) << "safety number must be order-independent so both peers compute the same string";
}

TEST(Identity, SafetyNumberIsStableForFixedPubkeys) {
    auto alice = fb::crypto::Identity::generate();
    auto bob   = fb::crypto::Identity::generate();
    const auto first  = fb::crypto::safety_number(alice.public_key(), bob.public_key());
    const auto second = fb::crypto::safety_number(alice.public_key(), bob.public_key());
    EXPECT_EQ(first, second);
}

TEST(Identity, SafetyNumberFormat) {
    auto alice = fb::crypto::Identity::generate();
    auto bob   = fb::crypto::Identity::generate();
    const auto sn = fb::crypto::safety_number(alice.public_key(), bob.public_key());
    // 12 groups of 5 digits separated by 11 spaces → 60 digits + 11 spaces = 71 chars.
    EXPECT_EQ(sn.size(), 71u);
    int digits = 0, spaces = 0;
    for (char c : sn) {
        if (c == ' ') ++spaces;
        else if (c >= '0' && c <= '9') ++digits;
        else ADD_FAILURE() << "unexpected char in safety number: " << c;
    }
    EXPECT_EQ(digits, 60);
    EXPECT_EQ(spaces, 11);
}

TEST(Identity, SafetyNumberChangesIfEitherPubkeyChanges) {
    auto alice = fb::crypto::Identity::generate();
    auto bob1  = fb::crypto::Identity::generate();
    auto bob2  = fb::crypto::Identity::generate();
    const auto sn1 = fb::crypto::safety_number(alice.public_key(), bob1.public_key());
    const auto sn2 = fb::crypto::safety_number(alice.public_key(), bob2.public_key());
    EXPECT_NE(sn1, sn2) << "swapping the peer must change the safety number (MITM detection)";
}

TEST(Identity, MoveDoesNotDoubleFree) {
    auto a = fb::crypto::Identity::generate();
    const auto pub_before = a.public_key();
    auto b = std::move(a);
    EXPECT_EQ(b.public_key(), pub_before);
    // Re-sign with b to confirm secret key transferred.
    const auto sig = b.sign(kHelloWorld);
    EXPECT_TRUE(fb::crypto::Identity::verify(b.public_key(), kHelloWorld, sig));
}
