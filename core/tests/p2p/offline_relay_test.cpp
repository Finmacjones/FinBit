// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// OfflineRelayStore gtests.
//
// Coverage:
//   - deposit + fetch round trip preserves bytes verbatim and FIFO order
//   - fetch returns ALL queued blobs and clears the bucket
//   - second fetch on already-empty bucket returns []
//   - per-recipient cap rejects excess deposits
//   - format checks: 31-byte recipient_pubkey rejected, empty payload rejected
//   - prune_expired drops past-TTL entries
//   - distinct recipients have independent FIFOs
// =============================================================================

#include "fb/p2p/offline_relay.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

namespace {

inline std::uint64_t real_now() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::span<const std::uint8_t> as_span(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

}  // namespace

TEST(OfflineRelay, DepositFetchRoundTrip) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    std::vector<std::uint8_t> blob{'h','i','b','o','b'};
    EXPECT_EQ(s.deposit(as_span(bob), as_span(blob)),
              fb::p2p::OfflineRelayStore::DepositResult::kAccepted);
    EXPECT_EQ(s.total_blobs(), 1u);
    auto out = s.fetch_and_clear(as_span(bob));
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], blob);
    EXPECT_EQ(s.total_blobs(), 0u);
}

TEST(OfflineRelay, FifoOrderingAcrossMultipleDeposits) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    for (int i = 0; i < 5; ++i) {
        std::vector<std::uint8_t> blob{static_cast<std::uint8_t>(i)};
        EXPECT_EQ(s.deposit(as_span(bob), as_span(blob)),
                  fb::p2p::OfflineRelayStore::DepositResult::kAccepted);
    }
    auto out = s.fetch_and_clear(as_span(bob));
    ASSERT_EQ(out.size(), 5u);
    for (int i = 0; i < 5; ++i) {
        ASSERT_EQ(out[i].size(), 1u);
        EXPECT_EQ(out[i][0], static_cast<std::uint8_t>(i));
    }
}

TEST(OfflineRelay, SecondFetchAfterClearReturnsEmpty) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    s.deposit(as_span(bob), as_span(std::vector<std::uint8_t>{1, 2}));
    EXPECT_EQ(s.fetch_and_clear(as_span(bob)).size(), 1u);
    EXPECT_EQ(s.fetch_and_clear(as_span(bob)).size(), 0u);
}

TEST(OfflineRelay, MalformedRecipientRejected) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> short_pub(31, 0xaa);
    EXPECT_EQ(s.deposit(as_span(short_pub), as_span(std::vector<std::uint8_t>{1})),
              fb::p2p::OfflineRelayStore::DepositResult::kRejectedFormat);
    EXPECT_EQ(s.total_blobs(), 0u);
}

TEST(OfflineRelay, EmptyPayloadRejected) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    std::vector<std::uint8_t> empty;
    EXPECT_EQ(s.deposit(as_span(bob), as_span(empty)),
              fb::p2p::OfflineRelayStore::DepositResult::kRejectedFormat);
}

TEST(OfflineRelay, PerRecipientCapStopsExcessDeposits) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    for (std::size_t i = 0; i < fb::p2p::kMaxBlobsPerRecipient; ++i) {
        ASSERT_EQ(s.deposit(as_span(bob), as_span(std::vector<std::uint8_t>{1})),
                  fb::p2p::OfflineRelayStore::DepositResult::kAccepted);
    }
    EXPECT_EQ(s.deposit(as_span(bob), as_span(std::vector<std::uint8_t>{1})),
              fb::p2p::OfflineRelayStore::DepositResult::kRejectedFull);
    EXPECT_EQ(s.total_blobs(), fb::p2p::kMaxBlobsPerRecipient);
}

TEST(OfflineRelay, PruneExpiredDropsOldBlobs) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    const auto base = real_now() - 8ULL * 24 * 60 * 60 * 1000;   // 8 days ago
    s.deposit(as_span(bob), as_span(std::vector<std::uint8_t>{1}), base);
    s.deposit(as_span(bob), as_span(std::vector<std::uint8_t>{2}), real_now());
    EXPECT_EQ(s.total_blobs(), 2u);
    EXPECT_EQ(s.prune_expired(), 1u);   // the 8-day-old one
    EXPECT_EQ(s.total_blobs(), 1u);
}

TEST(OfflineRelay, DistinctRecipientsAreIndependent) {
    fb::p2p::OfflineRelayStore s;
    std::vector<std::uint8_t> bob(32, 0xb0);
    std::vector<std::uint8_t> carol(32, 0xc0);
    s.deposit(as_span(bob),   as_span(std::vector<std::uint8_t>{1}));
    s.deposit(as_span(carol), as_span(std::vector<std::uint8_t>{2}));
    EXPECT_EQ(s.recipients(), 2u);
    auto bob_out = s.fetch_and_clear(as_span(bob));
    EXPECT_EQ(bob_out.size(), 1u);
    EXPECT_EQ(bob_out[0][0], 1);
    auto carol_out = s.fetch_and_clear(as_span(carol));
    EXPECT_EQ(carol_out.size(), 1u);
    EXPECT_EQ(carol_out[0][0], 2);
}
