// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/ratelimit/token_bucket.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <thread>

TEST(TokenBucket, ConsumesUpToBurst) {
    fb::ratelimit::TokenBucket b(/*rate=*/1000, /*burst=*/100);
    EXPECT_TRUE(b.try_consume(60));
    EXPECT_TRUE(b.try_consume(40));
    // Bucket exhausted; ask for 1 byte — should fail (essentially zero refill in <1us).
    EXPECT_FALSE(b.try_consume(50));
}

TEST(TokenBucket, RefillsOverTime) {
    fb::ratelimit::TokenBucket b(/*rate=*/10000, /*burst=*/100);
    EXPECT_TRUE(b.try_consume(100));
    EXPECT_FALSE(b.try_consume(50));
    // Wait long enough that >50 tokens accumulate.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));  // 20ms * 10000 = 200 tokens
    EXPECT_TRUE(b.try_consume(50));
}

TEST(TokenBucket, NeverExceedsBurst) {
    fb::ratelimit::TokenBucket b(/*rate=*/1'000'000, /*burst=*/50);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    // Even after a long idle, we cap at burst.
    EXPECT_TRUE(b.try_consume(50));
    EXPECT_FALSE(b.try_consume(1));
}

TEST(KeyedLimiter, IndependentBucketsPerKey) {
    fb::ratelimit::KeyedLimiter k(/*rate=*/1000, /*burst=*/100);
    std::array<std::uint8_t, 4> a{1, 2, 3, 4};
    std::array<std::uint8_t, 4> b{5, 6, 7, 8};
    EXPECT_TRUE(k.try_consume(std::span<const std::uint8_t>(a), 100));
    EXPECT_FALSE(k.try_consume(std::span<const std::uint8_t>(a), 1));
    EXPECT_TRUE(k.try_consume(std::span<const std::uint8_t>(b), 100));
}
