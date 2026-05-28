// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/padding.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

using namespace fb::crypto;

namespace {

std::vector<std::uint8_t> bytes_of(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace

TEST(Padding, DefaultLadderIsStrictlyIncreasing) {
    auto buckets = default_padding_buckets();
    ASSERT_GE(buckets.size(), 2u);
    for (std::size_t i = 1; i < buckets.size(); ++i) {
        EXPECT_GT(buckets[i], buckets[i - 1]) << "ladder not strictly increasing at i=" << i;
    }
    // The smallest bucket must be > 0 (we need at least 1 byte for the 0x80 marker).
    EXPECT_GT(buckets.front(), 0u);
}

TEST(Padding, SmallPlaintextPadsToSmallestBucket) {
    auto p = pad_to_bucket(bytes_of("ok"));
    EXPECT_EQ(p.size(), 256u);
    // Original bytes preserved at the start.
    EXPECT_EQ(p[0], 'o');
    EXPECT_EQ(p[1], 'k');
    // Marker at the original-length offset.
    EXPECT_EQ(p[2], 0x80);
    // Tail all zero.
    for (std::size_t i = 3; i < p.size(); ++i) EXPECT_EQ(p[i], 0x00);
}

TEST(Padding, BoundaryAtBucketMinusOneFitsInSameBucket) {
    // Plaintext of 255 bytes + 1-byte marker = 256 = smallest bucket exactly.
    std::vector<std::uint8_t> pt(255, 'A');
    auto p = pad_to_bucket(pt);
    EXPECT_EQ(p.size(), 256u);
    EXPECT_EQ(p[255], 0x80);
}

TEST(Padding, BoundaryAtBucketSizePromotesToNextBucket) {
    // 256-byte plaintext + 1-byte marker = 257 > 256 → next bucket (1024).
    std::vector<std::uint8_t> pt(256, 'B');
    auto p = pad_to_bucket(pt);
    EXPECT_EQ(p.size(), 1024u);
    EXPECT_EQ(p[256], 0x80);
}

TEST(Padding, RoundTripPreservesPlaintext) {
    for (const std::string& s : {
             std::string("hi"),
             std::string("a longer message that comfortably fits in the smallest bucket"),
             std::string(800, 'x'),    // bumps to 1024
             std::string(2000, 'y'),   // bumps to 4096
         }) {
        auto orig = bytes_of(s);
        auto padded = pad_to_bucket(orig);
        auto recovered = strip_padding(padded);
        EXPECT_EQ(recovered, orig) << "round-trip failed for len=" << s.size();
    }
}

TEST(Padding, RejectsOverlargePlaintext) {
    // Largest default bucket is 65536 — feed plaintext one byte too big to
    // force "exceeds largest bucket" (need plaintext.size()+1 > 65536).
    std::vector<std::uint8_t> too_big(65536, 'z');
    EXPECT_THROW({ (void)pad_to_bucket(too_big); }, PaddingError);
}

TEST(Padding, StripRejectsAllZero) {
    std::vector<std::uint8_t> all_zero(64, 0);
    EXPECT_THROW({ (void)strip_padding(all_zero); }, PaddingError);
}

TEST(Padding, StripRejectsMissingMarker) {
    // Looks padded-shaped but the byte before the zero tail isn't 0x80.
    std::vector<std::uint8_t> bad(64, 0);
    bad[0] = 'h';
    bad[1] = 'i';
    bad[2] = 0x42;  // not the 0x80 marker
    EXPECT_THROW({ (void)strip_padding(bad); }, PaddingError);
}

TEST(Padding, EmptyPlaintextStillFitsSmallestBucket) {
    auto p = pad_to_bucket(std::vector<std::uint8_t>{});
    EXPECT_EQ(p.size(), 256u);
    EXPECT_EQ(p[0], 0x80);
    auto r = strip_padding(p);
    EXPECT_TRUE(r.empty());
}

TEST(Padding, CustomLadder) {
    std::array<std::size_t, 2> custom{16, 64};
    auto p = pad_to_bucket(bytes_of("short"),
                            std::span<const std::size_t>(custom.data(), custom.size()));
    EXPECT_EQ(p.size(), 16u);
    EXPECT_EQ(p[5], 0x80);
}

TEST(Padding, CipherTextsForDifferentPlaintextsClusterToSameBucket) {
    // The whole POINT: a 5-byte and a 200-byte plaintext look identical on the
    // wire (both pad to 256). A passive observer can't distinguish them by size.
    auto p_small = pad_to_bucket(bytes_of("hello"));
    auto p_big   = pad_to_bucket(std::vector<std::uint8_t>(200, 'x'));
    EXPECT_EQ(p_small.size(), p_big.size());
    EXPECT_EQ(p_small.size(), 256u);
}
