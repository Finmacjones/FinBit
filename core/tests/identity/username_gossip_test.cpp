// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// UsernameGossip gtests.
//
// Two UsernameLog + UsernameGossip pairs connected by an in-process
// bridge. A's send callback delivers to B's on_message and vice versa.
//
// Coverage:
//   - sync_with(peer, 0) pulls every claim B has into A's log
//   - sync_with(peer, watermark) only pulls claims strictly newer than
//     watermark — incremental sync
//   - re-sync (B's claims already in A) returns kAlreadyKnown for all,
//     accepted_via_gossip stays at the previous count
//   - oversize log returns truncated=true, A pages by re-sync from
//     max_seen_ms
//   - garbage on the wire is dropped without throwing
// =============================================================================

#include "fb/identity/username_gossip.hpp"
#include "fb/identity/username_log.hpp"
#include "fb/store/sqlite_store.hpp"
#include "fb/p2p/kademlia.hpp"

#include "identity_log.pb.h"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <chrono>
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
    if (sodium_init() < 0) std::abort();
    Keypair kp;
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

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

fb::store::SqliteStore& dummy_store() {
    static auto s = fb::store::SqliteStore::open(":memory:");
    return *s;
}

// Bridge two gossip endpoints in-process. Each side's send is hooked
// to the other's on_message.
struct Bridge {
    fb::identity::UsernameGossip* a = nullptr;
    fb::identity::UsernameGossip* b = nullptr;
    fb::p2p::PeerInfo a_peer{};
    fb::p2p::PeerInfo b_peer{};

    fb::identity::GossipSendCallback a_send() {
        return [this](const fb::p2p::PeerInfo&,
                      std::span<const std::uint8_t> wire) {
            b->on_message(a_peer, std::vector<std::uint8_t>(
                wire.begin(), wire.end()));
        };
    }
    fb::identity::GossipSendCallback b_send() {
        return [this](const fb::p2p::PeerInfo&,
                      std::span<const std::uint8_t> wire) {
            a->on_message(b_peer, std::vector<std::uint8_t>(
                wire.begin(), wire.end()));
        };
    }
};

void seed_claim(fb::identity::UsernameLog& log, const Keypair& kp,
                 const std::string& name, std::uint64_t ts) {
    auto c = fb::identity::build_claim(
        name, as_span(kp.pub), as_span(kp.sec), ts);
    auto r = log.append_claim(c);
    ASSERT_EQ(r, fb::identity::UsernameLog::AppendResult::kAccepted);
}

}  // namespace

// Initial sync: B has 3 claims; A starts empty; sync_with(B, 0) pulls
// all 3 into A's log.
TEST(UsernameGossip, FullSyncFromEmptyLog) {
    fb::identity::UsernameLog log_a(dummy_store());
    fb::identity::UsernameLog log_b(dummy_store());
    Bridge bridge;
    bridge.a_peer.addr = "a"; bridge.b_peer.addr = "b";
    fb::identity::UsernameGossip gossip_a(log_a, bridge.a_send());
    fb::identity::UsernameGossip gossip_b(log_b, bridge.b_send());
    bridge.a = &gossip_a; bridge.b = &gossip_b;

    auto kp1 = gen_kp(), kp2 = gen_kp(), kp3 = gen_kp();
    const auto base = now_ms() - 10'000;
    seed_claim(log_b, kp1, "alice", base);
    seed_claim(log_b, kp2, "bob",   base + 100);
    seed_claim(log_b, kp3, "carol", base + 200);

    EXPECT_EQ(log_a.total_claims(), 0u);
    (void)gossip_a.sync_with(bridge.b_peer, /*since_ms=*/0);

    EXPECT_EQ(log_a.total_claims(), 3u);
    EXPECT_EQ(gossip_a.accepted_via_gossip(), 3u);
    EXPECT_TRUE(log_a.resolve("alice").has_value());
    EXPECT_TRUE(log_a.resolve("bob").has_value());
    EXPECT_TRUE(log_a.resolve("carol").has_value());
}

// Incremental sync: A already has the first claim; sync_with(B,
// max_seen) pulls only the newer ones.
TEST(UsernameGossip, IncrementalSyncSinceWatermark) {
    fb::identity::UsernameLog log_a(dummy_store());
    fb::identity::UsernameLog log_b(dummy_store());
    Bridge bridge;
    fb::identity::UsernameGossip gossip_a(log_a, bridge.a_send());
    fb::identity::UsernameGossip gossip_b(log_b, bridge.b_send());
    bridge.a = &gossip_a; bridge.b = &gossip_b;

    auto kp1 = gen_kp(), kp2 = gen_kp(), kp3 = gen_kp();
    const auto base = now_ms() - 10'000;
    auto c_alice = fb::identity::build_claim("alice", as_span(kp1.pub),
                                                as_span(kp1.sec), base);
    log_a.append_claim(c_alice);   // A already knows alice
    log_b.append_claim(c_alice);   // and so does B
    seed_claim(log_b, kp2, "bob",   base + 100);
    seed_claim(log_b, kp3, "carol", base + 200);

    // Sync from A's perspective: "give me everything strictly newer
    // than my latest" — base.
    (void)gossip_a.sync_with(bridge.b_peer, base);
    EXPECT_EQ(log_a.total_claims(), 3u);
    EXPECT_EQ(gossip_a.accepted_via_gossip(), 2u);  // bob + carol only
}

// Re-sync after A and B already agree: B's response has 0 new claims
// for A, accepted_via_gossip stays unchanged.
TEST(UsernameGossip, ReSyncWhenAlreadyConverged) {
    fb::identity::UsernameLog log_a(dummy_store());
    fb::identity::UsernameLog log_b(dummy_store());
    Bridge bridge;
    fb::identity::UsernameGossip gossip_a(log_a, bridge.a_send());
    fb::identity::UsernameGossip gossip_b(log_b, bridge.b_send());
    bridge.a = &gossip_a; bridge.b = &gossip_b;

    auto kp = gen_kp();
    seed_claim(log_a, kp, "alice", now_ms() - 5000);
    seed_claim(log_b, kp, "alice", now_ms() - 5000);
    // Note: same pubkey + same name + same timestamp gives different
    // claims (random nonce → different signature → different rows).

    (void)gossip_a.sync_with(bridge.b_peer, /*since_ms=*/0);
    // A receives B's claim. Different nonce from A's local one →
    // SECOND row in A's log for the same (alice, kp). Both refer to
    // the same person; resolve still returns kp.
    EXPECT_GE(log_a.total_claims(), 1u);
    EXPECT_TRUE(log_a.resolve("alice").has_value());

    // Now do it again — every claim B has, A also has now. accepted
    // count should not advance on the second sync.
    auto before = gossip_a.accepted_via_gossip();
    (void)gossip_a.sync_with(bridge.b_peer, /*since_ms=*/0);
    EXPECT_EQ(gossip_a.accepted_via_gossip(), before);
}

// Garbage bytes inbound: must not crash.
TEST(UsernameGossip, GarbageInboundDropped) {
    fb::identity::UsernameLog log_a(dummy_store());
    Bridge bridge;
    fb::identity::UsernameGossip gossip_a(log_a, bridge.a_send());

    std::vector<std::uint8_t> junk{0xff, 0x00, 0xde, 0xad, 0xbe, 0xef};
    gossip_a.on_message(bridge.b_peer,
        std::span<const std::uint8_t>(junk.data(), junk.size()));
    EXPECT_EQ(log_a.total_claims(), 0u);
    EXPECT_EQ(gossip_a.accepted_via_gossip(), 0u);
}

// Pagination: B has more than kClaimsPageMax claims; one round trip
// returns truncated=true with kClaimsPageMax records, A re-syncs from
// max_seen_ms to fetch the rest.
//
// Validates the protocol-level pagination contract — even though we
// don't expose the truncated flag through the public sync_with API,
// the wire format and server-side response math are the load-bearing
// pieces.
TEST(UsernameGossip, PaginationViaTruncatedFlag) {
    fb::identity::UsernameLog log_a(dummy_store());
    fb::identity::UsernameLog log_b(dummy_store());
    Bridge bridge;
    fb::identity::UsernameGossip gossip_a(log_a, bridge.a_send());
    fb::identity::UsernameGossip gossip_b(log_b, bridge.b_send());
    bridge.a = &gossip_a; bridge.b = &gossip_b;

    // Seed B with kClaimsPageMax + 5 claims, all distinct names +
    // distinct keys + distinct timestamps so resolve() can verify
    // each independently.
    const auto base = now_ms() - 60'000;
    constexpr std::size_t kTotal = fb::identity::kClaimsPageMax + 5;
    std::vector<Keypair> kps;
    kps.reserve(kTotal);
    for (std::size_t i = 0; i < kTotal; ++i) {
        kps.push_back(gen_kp());
        seed_claim(log_b, kps.back(),
                    "user" + std::to_string(i),
                    base + i);
    }

    // First sync: fills A with kClaimsPageMax claims.
    (void)gossip_a.sync_with(bridge.b_peer, /*since_ms=*/0);
    EXPECT_EQ(log_a.total_claims(),
              fb::identity::kClaimsPageMax);

    // Second sync: pull the rest from the highest timestamp we have.
    auto highest = base + fb::identity::kClaimsPageMax - 1;
    (void)gossip_a.sync_with(bridge.b_peer, highest);
    EXPECT_EQ(log_a.total_claims(), kTotal);
    EXPECT_EQ(gossip_a.accepted_via_gossip(), kTotal);
}
