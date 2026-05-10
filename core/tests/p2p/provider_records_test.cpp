// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// ProviderStore gtests.
//
// Coverage:
//   - canonical_signing_bytes deterministic + sensitive to every input
//   - build_record produces a record that ProviderStore::put accepts
//   - put: kAccepted / kAlreadyKnown / kRejectedSig / kRejectedFormat /
//          kRejectedClock / kRejectedExpired
//   - get returns matching pubkey records, skips expired
//   - prune_expired drops only past-TTL records, returns count
//   - multi-homed peer (multiple records with different nonces) coexist
// =============================================================================

#include "fb/p2p/provider_records.hpp"

#include "dht.pb.h"

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

constexpr std::uint64_t kT0  = 1'700'000'000'000ULL;   // some 2023 epoch
constexpr std::uint64_t kTtl = 60 * 60 * 1000;         // 1 hour
constexpr std::uint64_t kNow = kT0 + 60 * 1000;        // 1 minute later

}  // namespace

TEST(ProviderRecordCanonical, Deterministic) {
    auto kp = gen_kp();
    std::array<std::uint8_t, 16> nonce{};
    nonce[0] = 0x77;
    std::vector<std::string> addrs{ "wss://1.2.3.4:443", "wss://[::1]:443" };
    auto a = fb::p2p::canonical_signing_bytes(
        as_span(kp.pub), addrs, kT0, kTtl,
        std::span<const std::uint8_t>(nonce));
    auto b = fb::p2p::canonical_signing_bytes(
        as_span(kp.pub), addrs, kT0, kTtl,
        std::span<const std::uint8_t>(nonce));
    EXPECT_EQ(a, b);
}

TEST(ProviderRecordCanonical, SensitiveToEachInput) {
    auto kp1 = gen_kp();
    auto kp2 = gen_kp();
    std::array<std::uint8_t, 16> n1{}; n1[0] = 1;
    std::array<std::uint8_t, 16> n2{}; n2[0] = 2;
    std::vector<std::string> addrs1{ "wss://a:1" };
    std::vector<std::string> addrs2{ "wss://b:2" };
    auto base = fb::p2p::canonical_signing_bytes(
        as_span(kp1.pub), addrs1, 100, 200,
        std::span<const std::uint8_t>(n1));
    EXPECT_NE(base, fb::p2p::canonical_signing_bytes(
        as_span(kp2.pub), addrs1, 100, 200, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::p2p::canonical_signing_bytes(
        as_span(kp1.pub), addrs2, 100, 200, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::p2p::canonical_signing_bytes(
        as_span(kp1.pub), addrs1, 101, 200, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::p2p::canonical_signing_bytes(
        as_span(kp1.pub), addrs1, 100, 201, std::span<const std::uint8_t>(n1)));
    EXPECT_NE(base, fb::p2p::canonical_signing_bytes(
        as_span(kp1.pub), addrs1, 100, 200, std::span<const std::uint8_t>(n2)));
}

TEST(ProviderStore, AcceptedThenIdempotent) {
    auto kp = gen_kp();
    auto rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://203.0.113.5:443" }, kT0, kTtl);
    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kAccepted);
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kAlreadyKnown);
    EXPECT_EQ(store.size(), 1u);
}

TEST(ProviderStore, GetReturnsMatchingPubkey) {
    auto kp = gen_kp();
    auto rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://203.0.113.5:443" }, kT0, kTtl);
    fb::p2p::ProviderStore store;
    store.put(rec, kNow);
    auto got = store.get(as_span(kp.pub), kNow);
    ASSERT_EQ(got.size(), 1u);
    ASSERT_EQ(got[0].addresses_size(), 1);
    EXPECT_EQ(got[0].addresses(0), "wss://203.0.113.5:443");
}

TEST(ProviderStore, GetUnknownReturnsEmpty) {
    auto kp = gen_kp();
    fb::p2p::ProviderStore store;
    EXPECT_TRUE(store.get(as_span(kp.pub), kNow).empty());
}

TEST(ProviderStore, BadSignatureRejected) {
    auto kp = gen_kp();
    auto rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://1.2.3.4:443" }, kT0, kTtl);
    auto sig = rec.signature();
    sig[0] ^= 0x01;
    rec.set_signature(sig);
    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kRejectedSig);
}

// Spoofed publisher attack: attacker has their OWN valid keypair,
// generates a real signed record advertising their own routes, then
// rewrites publisher_pubkey to the VICTIM's pubkey hoping the
// receiver only checks the signature against the bytes-as-they-look.
// The receiver must verify the signature against publisher_pubkey
// (which is now the victim's), and that verification must fail
// because the signature was produced under attacker's secret key.
TEST(ProviderStore, SpoofedPublisherPubkeyRejected) {
    auto attacker = gen_kp();
    auto victim   = gen_kp();
    auto rec = fb::p2p::build_record(
        as_span(attacker.pub), as_span(attacker.sec),
        { "wss://attacker.evil:443" }, kT0, kTtl);
    // Rewrite publisher_pubkey to the victim's identity, keep the
    // attacker's signature intact. A naive receiver that only checks
    // "does the signature decode" without checking against
    // publisher_pubkey would accept this.
    rec.set_publisher_pubkey(std::string(victim.pub.begin(), victim.pub.end()));
    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kRejectedSig)
        << "store accepted a record whose signature was made under "
           "a key OTHER than the claimed publisher_pubkey";
}

TEST(ProviderStore, EmptyAddressListRejected) {
    auto kp = gen_kp();
    fb::proto::ProviderRecord rec;
    rec.set_publisher_pubkey(std::string(kp.pub.begin(), kp.pub.end()));
    rec.set_published_at_ms(kT0);
    rec.set_ttl_ms(kTtl);
    rec.set_nonce(std::string(16, '\0'));
    rec.set_signature(std::string(crypto_sign_BYTES, '\0'));
    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kRejectedFormat);
}

TEST(ProviderStore, FutureTimestampRejected) {
    auto kp = gen_kp();
    auto rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://1.2.3.4:443" },
        /*published_at_ms=*/kNow + 60 * 60 * 1000,   // 1 hour future
        /*ttl_ms=*/kTtl);
    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kRejectedClock);
}

TEST(ProviderStore, AlreadyExpiredRejected) {
    auto kp = gen_kp();
    auto rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://1.2.3.4:443" }, kT0, /*ttl=*/100);   // 100ms TTL
    fb::p2p::ProviderStore store;
    // now is far past published_at + ttl
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kRejectedExpired);
}

TEST(ProviderStore, ExpiredRecordsSkippedByGetAndPruned) {
    auto kp = gen_kp();
    // Two records: one fresh, one expiring soon.
    auto fresh = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://fresh:443" }, kT0, /*ttl=*/24 * 60 * 60 * 1000);   // 24h
    auto stale = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://stale:443" }, kT0, /*ttl=*/30 * 1000);             // 30s

    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(fresh, kT0 + 1000),
              fb::p2p::ProviderStore::PutResult::kAccepted);
    EXPECT_EQ(store.put(stale, kT0 + 1000),
              fb::p2p::ProviderStore::PutResult::kAccepted);
    EXPECT_EQ(store.size(), 2u);

    // 5 minutes later, stale is expired but fresh isn't.
    const std::uint64_t later = kT0 + 5 * 60 * 1000;
    auto got = store.get(as_span(kp.pub), later);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].addresses(0), "wss://fresh:443");

    // prune_expired drops the stale record + reports 1.
    EXPECT_EQ(store.prune_expired(later), 1u);
    EXPECT_EQ(store.size(), 1u);
}

// I4: offline_relays field round-trips through build_record + put +
// get + verify. Distinct relay lists produce different canonical
// signing bytes (so a peer can't lie about a relay set without
// invalidating the signature).
TEST(ProviderStore, OfflineRelaysRoundTripAndAreSigned) {
    auto kp = gen_kp();
    std::vector<std::uint8_t> relay_a(32, 0xa1);
    std::vector<std::uint8_t> relay_b(32, 0xb2);
    std::vector<std::vector<std::uint8_t>> relays{ relay_a, relay_b };

    auto rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        std::vector<std::string>{ "wss://1.2.3.4:443" },
        kT0, kTtl, relays);
    fb::p2p::ProviderStore store;
    EXPECT_EQ(store.put(rec, kNow),
              fb::p2p::ProviderStore::PutResult::kAccepted);

    auto got = store.get(as_span(kp.pub), kNow);
    ASSERT_EQ(got.size(), 1u);
    ASSERT_EQ(got[0].offline_relays_size(), 2);
    EXPECT_EQ(got[0].offline_relays(0),
              std::string(relay_a.begin(), relay_a.end()));
    EXPECT_EQ(got[0].offline_relays(1),
              std::string(relay_b.begin(), relay_b.end()));

    // Now mutate: change one relay byte and re-verify the same
    // record (without re-signing). Should be rejected.
    auto tampered = rec;
    auto* mut = tampered.mutable_offline_relays(0);
    if (!mut->empty()) (*mut)[0] = 0xff;
    fb::p2p::ProviderStore store2;
    EXPECT_EQ(store2.put(tampered, kNow),
              fb::p2p::ProviderStore::PutResult::kRejectedSig);
}

TEST(ProviderStore, MultiHomedRecordsCoexist) {
    // Same publisher publishes TWO different records (e.g., one over WSS
    // and one over QUIC) with different nonces. Both should live under
    // the same publisher key and both come back from get().
    auto kp = gen_kp();
    auto wss_rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "wss://203.0.113.5:443" }, kT0, kTtl);
    auto tcp_rec = fb::p2p::build_record(
        as_span(kp.pub), as_span(kp.sec),
        { "tcp://203.0.113.5:9000" }, kT0 + 1000, kTtl);
    fb::p2p::ProviderStore store;
    store.put(wss_rec, kNow);
    store.put(tcp_rec, kNow);
    auto got = store.get(as_span(kp.pub), kNow);
    EXPECT_EQ(got.size(), 2u);
}
