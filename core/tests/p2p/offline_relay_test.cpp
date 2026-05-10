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

#include "fb/crypto/ratchet.hpp"
#include <sodium.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
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

// Opacity: a peer acting as an OFFLINE_DEPOSIT relay holds AEAD-
// encrypted Envelope ciphertext, NOT plaintext. The relay's view of
// the deposited blob (whatever bytes Alice handed it via deposit())
// must not contain the plaintext canary that Alice sent. This is the
// property the README claims: "The central server [or friend-relay]
// remains an optional fallback for unreachable peers, never sees
// envelope contents."
//
// We exercise the actual production path: Alice's Double Ratchet
// produces ciphertext; the ciphertext is what the relay receives via
// deposit(); the relay's internal blob exactly equals what fetch()
// returns, and that blob must not contain the canary.
TEST(OfflineRelay, RelayCannotReadDepositedEnvelopeContents) {
    sodium_init();

    // Set up a Double Ratchet pair so we can produce real ciphertext.
    std::array<std::uint8_t, 32> shared{};
    for (std::size_t i = 0; i < shared.size(); ++i) {
        shared[i] = static_cast<std::uint8_t>(0xC3 ^ i);
    }
    std::array<std::uint8_t, 32> bob_priv{};
    randombytes_buf(bob_priv.data(), bob_priv.size());
    std::array<std::uint8_t, 32> bob_pub{};
    ASSERT_EQ(0, crypto_scalarmult_base(bob_pub.data(), bob_priv.data()));
    auto alice = fb::crypto::DoubleRatchet::init_alice(shared, bob_pub);

    // Alice encrypts a known canary.
    const std::string canary =
        "OPACITY-CANARY-deadbeef-friend-relay-must-not-see-this";
    std::vector<std::uint8_t> aad{0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> plaintext(canary.begin(), canary.end());
    auto ct = alice.encrypt(
        std::span<const std::uint8_t>(plaintext.data(), plaintext.size()),
        std::span<const std::uint8_t>(aad.data(), aad.size()));

    // The "envelope" the relay sees is the ratchet ciphertext (in the
    // production path it's a wire-form fb::proto::Envelope wrapping
    // ct; for opacity testing the wrapper adds nothing — only ct
    // could possibly leak plaintext).
    fb::p2p::OfflineRelayStore relay;
    std::vector<std::uint8_t> bob_id(32, 0xb0);
    ASSERT_EQ(relay.deposit(as_span(bob_id), as_span(ct)),
              fb::p2p::OfflineRelayStore::DepositResult::kAccepted);

    // The relay operator inspects what they're holding — fetch is
    // exactly what they have access to via the storage layer.
    auto held = relay.fetch_and_clear(as_span(bob_id));
    ASSERT_EQ(held.size(), 1u);
    const auto& blob = held[0];

    // Plaintext canary must NOT appear in the blob bytes.
    auto find_substr = [&](std::string_view needle) {
        if (needle.size() > blob.size()) return false;
        for (std::size_t i = 0; i + needle.size() <= blob.size(); ++i) {
            if (std::memcmp(blob.data() + i, needle.data(),
                              needle.size()) == 0) {
                return true;
            }
        }
        return false;
    };
    EXPECT_FALSE(find_substr(canary))
        << "relay can read the full plaintext canary it deposited — "
           "AEAD layer is broken";
    // Also scan for short substrings — even a 6-byte plaintext run
    // appearing here would be a structural leak.
    for (std::size_t L = 6; L <= 16 && L <= canary.size(); L += 2) {
        for (std::size_t i = 0; i + L <= canary.size(); ++i) {
            std::string_view sub(canary.data() + i, L);
            EXPECT_FALSE(find_substr(sub))
                << "relay sees " << L << "-byte plaintext substring "
                   "starting at canary offset " << i << ": " << sub;
        }
    }
}
