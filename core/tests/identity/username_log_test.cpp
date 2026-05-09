// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// UsernameLog gtests.
//
// Coverage:
//   - is_valid_username: edge cases on charset / length / leading-or-trailing
//     punctuation.
//   - canonical_signing_bytes: same inputs → same bytes; different inputs
//     → different bytes (no accidental collisions on the canonical layout).
//   - build_claim: signs in a way that verify_claim_signature accepts.
//   - append_claim: kAccepted / kAlreadyKnown / kRejectedFormat /
//     kRejectedSig / kRejectedClock paths.
//   - resolve: returns the smallest-timestamp winner; updates if an older
//     claim arrives later (eventual consistency through partition healing).
//   - usernames_of: returns every username for a pubkey ordered by ts.
//   - claims_since: pagination + ordering + max cap.
// =============================================================================

#include "fb/identity/username_log.hpp"
#include "fb/store/sqlite_store.hpp"

#include "identity_log.pb.h"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

struct Keypair {
    std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> sec{};
};

Keypair gen_kp() {
    Keypair kp;
    if (sodium_init() < 0) std::abort();
    crypto_sign_keypair(kp.pub.data(), kp.sec.data());
    return kp;
}

std::span<const std::uint8_t> as_span(const std::array<std::uint8_t,
    crypto_sign_PUBLICKEYBYTES>& a) {
    return std::span<const std::uint8_t>(a.data(), a.size());
}
std::span<const std::uint8_t> as_span(const std::array<std::uint8_t,
    crypto_sign_SECRETKEYBYTES>& a) {
    return std::span<const std::uint8_t>(a.data(), a.size());
}

constexpr std::uint64_t kT0 = 1'700'000'000'000ULL;   // some 2023 epoch ms

// Helper: a "now_ms" that ALWAYS dominates kT0 so clock-slop checks pass
// independent of the wall clock.
constexpr std::uint64_t kNow = kT0 + 24 * 60 * 60 * 1000;

// Throwaway in-memory store; UsernameLog opens its own :memory: handle
// today but the API still accepts a store reference.
fb::store::SqliteStore& dummy_store() {
    static auto s = fb::store::SqliteStore::open(":memory:");
    return *s;
}

}  // namespace

TEST(UsernameValidation, AcceptsCanonicalShapes) {
    EXPECT_TRUE(fb::identity::is_valid_username("alice"));
    EXPECT_TRUE(fb::identity::is_valid_username("a1b2"));
    EXPECT_TRUE(fb::identity::is_valid_username("user.name"));
    EXPECT_TRUE(fb::identity::is_valid_username("u_n_d_e_r"));
    EXPECT_TRUE(fb::identity::is_valid_username("ab1"));      // min length
    // 32-char max length boundary
    EXPECT_TRUE(fb::identity::is_valid_username(
        std::string(32, 'a')));
}

TEST(UsernameValidation, RejectsMalformed) {
    EXPECT_FALSE(fb::identity::is_valid_username(""));
    EXPECT_FALSE(fb::identity::is_valid_username("ab"));    // too short
    EXPECT_FALSE(fb::identity::is_valid_username(
        std::string(33, 'a')));                              // too long
    EXPECT_FALSE(fb::identity::is_valid_username("Alice"));  // uppercase
    EXPECT_FALSE(fb::identity::is_valid_username("ali ce")); // space
    EXPECT_FALSE(fb::identity::is_valid_username("alice@x"));// @
    EXPECT_FALSE(fb::identity::is_valid_username("alice#1"));// #
    EXPECT_FALSE(fb::identity::is_valid_username(".alice")); // leading dot
    EXPECT_FALSE(fb::identity::is_valid_username("alice."));
    EXPECT_FALSE(fb::identity::is_valid_username("-alice"));
    EXPECT_FALSE(fb::identity::is_valid_username("alice-"));
}

TEST(CanonicalSigningBytes, Deterministic) {
    auto kp = gen_kp();
    std::array<std::uint8_t, 16> nonce{};
    auto a = fb::identity::canonical_signing_bytes(
        "alice", as_span(kp.pub), 1234, std::span<const std::uint8_t>(nonce));
    auto b = fb::identity::canonical_signing_bytes(
        "alice", as_span(kp.pub), 1234, std::span<const std::uint8_t>(nonce));
    EXPECT_EQ(a, b);
}

TEST(CanonicalSigningBytes, ChangingAnyInputChangesBytes) {
    auto kp1 = gen_kp();
    auto kp2 = gen_kp();
    std::array<std::uint8_t, 16> n1{}; n1[0] = 0x01;
    std::array<std::uint8_t, 16> n2{}; n2[0] = 0x02;
    auto base = fb::identity::canonical_signing_bytes(
        "alice", as_span(kp1.pub), 100, std::span<const std::uint8_t>(n1));
    EXPECT_NE(base, fb::identity::canonical_signing_bytes(
        "bob",   as_span(kp1.pub), 100, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::identity::canonical_signing_bytes(
        "alice", as_span(kp2.pub), 100, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::identity::canonical_signing_bytes(
        "alice", as_span(kp1.pub), 101, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::identity::canonical_signing_bytes(
        "alice", as_span(kp1.pub), 100, std::span<const std::uint8_t>(n2)));
}

TEST(BuildClaim, SignaturVerifiesAfterBuild) {
    auto kp = gen_kp();
    auto claim = fb::identity::build_claim(
        "alice", as_span(kp.pub), as_span(kp.sec), kT0);
    fb::identity::UsernameLog log(dummy_store());
    EXPECT_EQ(log.append_claim(claim, kNow),
              fb::identity::UsernameLog::AppendResult::kAccepted);
}

TEST(UsernameLog, AcceptThenIdempotent) {
    auto kp = gen_kp();
    auto claim = fb::identity::build_claim(
        "alice", as_span(kp.pub), as_span(kp.sec), kT0);
    fb::identity::UsernameLog log(dummy_store());
    EXPECT_EQ(log.append_claim(claim, kNow),
              fb::identity::UsernameLog::AppendResult::kAccepted);
    // Same exact claim again → kAlreadyKnown, no row added.
    EXPECT_EQ(log.append_claim(claim, kNow),
              fb::identity::UsernameLog::AppendResult::kAlreadyKnown);
    EXPECT_EQ(log.total_claims(), 1u);
}

TEST(UsernameLog, ResolveReturnsClaimedPubkey) {
    auto kp = gen_kp();
    auto claim = fb::identity::build_claim(
        "alice", as_span(kp.pub), as_span(kp.sec), kT0);
    fb::identity::UsernameLog log(dummy_store());
    log.append_claim(claim, kNow);
    auto resolved = log.resolve("alice");
    ASSERT_TRUE(resolved.has_value());
    EXPECT_TRUE(std::equal(resolved->begin(), resolved->end(),
                           kp.pub.begin()));
}

TEST(UsernameLog, ResolveUnknownReturnsNullopt) {
    fb::identity::UsernameLog log(dummy_store());
    EXPECT_FALSE(log.resolve("nobody").has_value());
}

TEST(UsernameLog, FormatRejected) {
    auto kp = gen_kp();
    // Build a manually-crafted claim with bad format (we can't call
    // build_claim because it pre-validates).
    fb::proto::UserClaim c;
    c.set_username("BAD#NAME");
    c.set_pubkey(std::string(kp.pub.begin(), kp.pub.end()));
    c.set_timestamp_ms(kT0);
    std::string nonce(16, '\0');
    c.set_nonce(nonce);
    c.set_signature(std::string(crypto_sign_BYTES, '\0'));
    fb::identity::UsernameLog log(dummy_store());
    EXPECT_EQ(log.append_claim(c, kNow),
              fb::identity::UsernameLog::AppendResult::kRejectedFormat);
}

TEST(UsernameLog, BadSignatureRejected) {
    auto kp = gen_kp();
    auto claim = fb::identity::build_claim(
        "alice", as_span(kp.pub), as_span(kp.sec), kT0);
    // Flip a bit in the signature.
    std::string sig = claim.signature();
    sig[0] ^= 0x01;
    claim.set_signature(sig);
    fb::identity::UsernameLog log(dummy_store());
    EXPECT_EQ(log.append_claim(claim, kNow),
              fb::identity::UsernameLog::AppendResult::kRejectedSig);
}

TEST(UsernameLog, FutureTimestampRejected) {
    auto kp = gen_kp();
    // 1 hour in the future at kNow → exceeds 5-min skew.
    auto claim = fb::identity::build_claim(
        "alice", as_span(kp.pub), as_span(kp.sec),
        kNow + 60 * 60 * 1000);
    fb::identity::UsernameLog log(dummy_store());
    EXPECT_EQ(log.append_claim(claim, kNow),
              fb::identity::UsernameLog::AppendResult::kRejectedClock);
}

TEST(UsernameLog, ConflictResolutionEventualConsistency) {
    // alice and bob both claim "alice" — alice's claim has a smaller
    // timestamp. If bob's claim arrives FIRST and alice's later, the log
    // must converge to alice as the winner.
    auto alice = gen_kp();
    auto bob   = gen_kp();
    auto alice_claim = fb::identity::build_claim(
        "alice", as_span(alice.pub), as_span(alice.sec), kT0);
    auto bob_claim   = fb::identity::build_claim(
        "alice", as_span(bob.pub),   as_span(bob.sec),   kT0 + 1000);
    fb::identity::UsernameLog log(dummy_store());

    // Bob's claim arrives first.
    EXPECT_EQ(log.append_claim(bob_claim, kNow),
              fb::identity::UsernameLog::AppendResult::kAccepted);
    auto winner1 = log.resolve("alice");
    ASSERT_TRUE(winner1.has_value());
    EXPECT_TRUE(std::equal(winner1->begin(), winner1->end(),
                           bob.pub.begin()));

    // Alice's older claim arrives via gossip — log converges.
    EXPECT_EQ(log.append_claim(alice_claim, kNow),
              fb::identity::UsernameLog::AppendResult::kAccepted);
    auto winner2 = log.resolve("alice");
    ASSERT_TRUE(winner2.has_value());
    EXPECT_TRUE(std::equal(winner2->begin(), winner2->end(),
                           alice.pub.begin()));

    // Both rows live in the log (resolve picks the winner, doesn't
    // delete the loser).
    EXPECT_EQ(log.total_claims(), 2u);
}

TEST(UsernameLog, UsernamesOfPubkeyOrderedByTimestamp) {
    auto kp = gen_kp();
    auto c1 = fb::identity::build_claim(
        "alice",  as_span(kp.pub), as_span(kp.sec), kT0 + 100);
    auto c2 = fb::identity::build_claim(
        "alice2", as_span(kp.pub), as_span(kp.sec), kT0 + 200);
    auto c3 = fb::identity::build_claim(
        "alice3", as_span(kp.pub), as_span(kp.sec), kT0 + 50);
    fb::identity::UsernameLog log(dummy_store());
    log.append_claim(c1, kNow);
    log.append_claim(c2, kNow);
    log.append_claim(c3, kNow);
    auto names = log.usernames_of(
        std::span<const std::uint8_t>(kp.pub.data(), kp.pub.size()));
    ASSERT_EQ(names.size(), 3u);
    EXPECT_EQ(names[0], "alice3");   // ts kT0+50
    EXPECT_EQ(names[1], "alice");    // ts kT0+100
    EXPECT_EQ(names[2], "alice2");   // ts kT0+200
}

TEST(UsernameLog, ClaimsSinceFiltersAndCaps) {
    fb::identity::UsernameLog log(dummy_store());
    auto kp = gen_kp();
    for (int i = 0; i < 5; ++i) {
        auto c = fb::identity::build_claim(
            "name" + std::to_string(i), as_span(kp.pub), as_span(kp.sec),
            kT0 + i * 1000);
        log.append_claim(c, kNow);
    }

    // Pull only entries strictly newer than kT0 + 1500 (claim with i=2,3,4).
    auto since = log.claims_since(kT0 + 1500, /*max=*/100);
    EXPECT_EQ(since.size(), 3u);
    // Cap at 2 — should return claims i=2,3 (ascending by timestamp).
    auto capped = log.claims_since(kT0 + 1500, /*max=*/2);
    ASSERT_EQ(capped.size(), 2u);
    EXPECT_EQ(capped[0].timestamp_ms(), kT0 + 2000);
    EXPECT_EQ(capped[1].timestamp_ms(), kT0 + 3000);
}
