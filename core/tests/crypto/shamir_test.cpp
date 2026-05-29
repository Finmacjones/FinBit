// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/shamir.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <vector>

using namespace fb::crypto;

namespace {

std::vector<std::uint8_t> bytes_of_length(std::size_t n, std::uint8_t seed_byte) {
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::uint8_t>((seed_byte * 31 + i * 7) & 0xff);
    }
    return out;
}

}  // namespace

// ---- Sanity ---------------------------------------------------------------

TEST(Shamir, SplitWithThreshold1IsTrivialCopyOfSecret) {
    auto secret = bytes_of_length(32, 0xAA);
    auto shares = shamir::split(secret, /*M=*/1, /*N=*/3);
    ASSERT_EQ(shares.size(), 3u);
    // Each share's y MUST equal the secret bytes (degree-0 polynomial = constant).
    for (const auto& s : shares) {
        EXPECT_EQ(s.y, secret);
    }
}

TEST(Shamir, RoundTripWithExactlyThresholdShares) {
    auto secret = bytes_of_length(32, 0x42);
    auto shares = shamir::split(secret, /*M=*/3, /*N=*/5);
    ASSERT_EQ(shares.size(), 5u);

    // Use the first 3 (M).
    std::vector<shamir::Share> chosen(shares.begin(), shares.begin() + 3);
    auto recovered = shamir::combine(chosen);
    EXPECT_EQ(recovered, secret);
}

TEST(Shamir, RoundTripWithMoreThanThresholdShares) {
    auto secret = bytes_of_length(32, 0xC3);
    auto shares = shamir::split(secret, /*M=*/3, /*N=*/5);
    auto recovered = shamir::combine(shares);   // all 5
    EXPECT_EQ(recovered, secret);
}

TEST(Shamir, RoundTripWithArbitrarySubsetOfThreshold) {
    auto secret = bytes_of_length(32, 0x55);
    auto shares = shamir::split(secret, /*M=*/3, /*N=*/5);
    // Try several distinct M-subsets — all must recover the same secret.
    for (auto subset : std::vector<std::array<std::size_t, 3>>{
            {0, 1, 2}, {0, 2, 4}, {1, 3, 4}, {0, 1, 4}, {2, 3, 4}}) {
        std::vector<shamir::Share> chosen{
            shares[subset[0]], shares[subset[1]], shares[subset[2]]};
        EXPECT_EQ(shamir::combine(chosen), secret);
    }
}

// ---- Information-theoretic security signal --------------------------------

TEST(Shamir, FewerThanThresholdSharesRevealNothing) {
    // The strict statement is information-theoretic: M-1 shares could
    // correspond to ANY secret with equal probability. We can't prove
    // that empirically, but we can confirm the WEAKER negative claim —
    // a degree-(M-1) polynomial interpolation from M-1 shares does NOT
    // produce the original secret (it produces some other value with
    // overwhelming probability for random secrets).
    auto secret = bytes_of_length(32, 0x99);
    auto shares = shamir::split(secret, /*M=*/3, /*N=*/5);

    // 2 shares (< M) — combine() does not throw, but the result must
    // not equal the secret (with overwhelming probability).
    std::vector<shamir::Share> two{shares[0], shares[1]};
    auto guessed = shamir::combine(two);
    EXPECT_NE(guessed, secret);
}

// ---- Failure modes --------------------------------------------------------

TEST(Shamir, SplitRejectsBadThresholds) {
    auto secret = bytes_of_length(8, 1);
    EXPECT_THROW({ (void)shamir::split(secret, 0, 3); }, shamir::ShamirError);
    EXPECT_THROW({ (void)shamir::split(secret, 4, 3); }, shamir::ShamirError);
    EXPECT_THROW({ (void)shamir::split(secret, 1, 0); }, shamir::ShamirError);
    EXPECT_THROW({ (void)shamir::split({}, 2, 3); },    shamir::ShamirError);
}

TEST(Shamir, CombineRejectsDuplicateX) {
    auto secret = bytes_of_length(8, 1);
    auto shares = shamir::split(secret, 2, 3);
    auto dup = shares[0];
    dup.x = shares[1].x;   // collide x-coords
    std::vector<shamir::Share> bad{shares[1], dup};
    EXPECT_THROW({ (void)shamir::combine(bad); }, shamir::ShamirError);
}

TEST(Shamir, CombineRejectsLengthMismatch) {
    auto secret = bytes_of_length(8, 1);
    auto shares = shamir::split(secret, 2, 3);
    shares[1].y.pop_back();
    EXPECT_THROW({ (void)shamir::combine(
        std::span<const shamir::Share>(shares.data(), 2)); },
                  shamir::ShamirError);
}

TEST(Shamir, EncodeDecodeRoundTrip) {
    auto secret = bytes_of_length(32, 0xEE);
    auto shares = shamir::split(secret, 2, 3);
    for (const auto& s : shares) {
        auto wire = shamir::encode_share(s);
        EXPECT_EQ(wire.size(), 1u + s.y.size());
        auto back = shamir::decode_share(
            std::span<const std::uint8_t>(wire.data(), wire.size()));
        EXPECT_EQ(back.x, s.x);
        EXPECT_EQ(back.y, s.y);
    }
}

TEST(Shamir, DecodeRejectsBadInputs) {
    std::vector<std::uint8_t> too_short = {0x05};
    EXPECT_THROW({ (void)shamir::decode_share(
        std::span<const std::uint8_t>(too_short.data(), too_short.size())); },
                  shamir::ShamirError);

    std::vector<std::uint8_t> zero_x = {0x00, 0x42, 0x43};
    EXPECT_THROW({ (void)shamir::decode_share(
        std::span<const std::uint8_t>(zero_x.data(), zero_x.size())); },
                  shamir::ShamirError);
}

// ---- Realistic identity-seed scenario -------------------------------------

TEST(Shamir, IdentitySeedSplitAcrossFiveContactsThreeRecover) {
    // Simulates the social-recovery flow: split the 32-byte Ed25519
    // identity seed across 5 trusted contacts with threshold 3. Lose 2
    // contacts (different ones each round) — any remaining 3 still
    // recover the seed.
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(0x10 + i);
    }
    auto shares = shamir::split(
        std::span<const std::uint8_t>(seed.data(), seed.size()), 3, 5);

    // Drop contact 0 and 4 — surviving 1,2,3 must recover.
    std::vector<shamir::Share> alive{shares[1], shares[2], shares[3]};
    auto recovered = shamir::combine(alive);
    ASSERT_EQ(recovered.size(), 32u);
    for (std::size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(recovered[i], seed[i]);
    }
}
