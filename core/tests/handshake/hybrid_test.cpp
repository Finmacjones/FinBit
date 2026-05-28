// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/handshake/hybrid.hpp"

#include "envelope.pb.h"
#include "handshake.pb.h"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using namespace fb::handshake;

// Build a deterministic Identity from a fixed seed so the test names a
// concrete pair of users (alice / bob) and the same seed → same Identity →
// same X25519 + same PQ keypair across runs.
fb::crypto::Identity ident_from_byte(std::uint8_t fill) {
    std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed{};
    for (auto& b : seed) b = fill;
    return fb::crypto::Identity::from_seed(seed);
}

std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed_of_byte(std::uint8_t fill) {
    std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed{};
    for (auto& b : seed) b = fill;
    return seed;
}

}  // namespace

TEST(Handshake, X25519DerivedFromIdentityIsConsistent) {
    auto alice = ident_from_byte(0x11);
    auto x_a1 = derive_x25519(alice);
    auto x_a2 = derive_x25519(alice);
    EXPECT_EQ(x_a1.pub, x_a2.pub);
    EXPECT_EQ(x_a1.priv, x_a2.priv);
}

TEST(Handshake, X25519DhMatchesOnBothSides) {
    auto alice = ident_from_byte(0x11);
    auto bob   = ident_from_byte(0x22);
    auto x_a = derive_x25519(alice);
    auto x_b = derive_x25519(bob);
    auto ab = derive_shared_secret(x_a,
        std::span<const std::uint8_t, 32>(x_b.pub.data(), 32));
    auto ba = derive_shared_secret(x_b,
        std::span<const std::uint8_t, 32>(x_a.pub.data(), 32));
    EXPECT_EQ(ab, ba);
}

TEST(Handshake, PqIdentityDerivationIsDeterministic) {
    auto alice = ident_from_byte(0x33);
    auto seed  = seed_of_byte(0x33);
    auto pq1 = derive_pq_identity(alice,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    auto pq2 = derive_pq_identity(alice,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    EXPECT_EQ(pq1.pub, pq2.pub);
    EXPECT_EQ(pq1.sec, pq2.sec);
    // The binding sig is deterministic in Ed25519 (RFC 8032) too.
    EXPECT_EQ(pq1.pubkey_sig, pq2.pubkey_sig);

    // And it actually verifies as a signature over pq.pub by the identity.
    EXPECT_TRUE(fb::crypto::Identity::verify(
        alice.public_key(),
        std::span<const std::uint8_t>(pq1.pub.data(), pq1.pub.size()),
        pq1.pubkey_sig));
}

TEST(Handshake, HybridSendRecvAgreeOnRoot) {
    auto alice = ident_from_byte(0x44);
    auto bob   = ident_from_byte(0x55);
    auto seed_alice = seed_of_byte(0x44);
    auto seed_bob   = seed_of_byte(0x55);

    auto x_alice = derive_x25519(alice);
    auto x_bob   = derive_x25519(bob);
    auto pq_bob  = derive_pq_identity(bob,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed_bob));

    // Alice → Bob: encap against Bob's PQ pubkey + Bob's X25519.
    auto send = derive_hybrid_send(x_alice,
        std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32),
        std::span<const std::uint8_t>(pq_bob.pub.data(), pq_bob.pub.size()));

    // Bob recovers the same root via his PQ secret + Alice's X25519.
    auto recv = derive_hybrid_recv(x_bob,
        std::span<const std::uint8_t, 32>(x_alice.pub.data(), 32),
        std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SecBytes>(
            pq_bob.sec.data(), pq_bob.sec.size()),
        std::span<const std::uint8_t>(send.pq_ct.data(), send.pq_ct.size()));

    EXPECT_EQ(send.shared, recv);
    EXPECT_FALSE(send.pq_ct.empty());
    EXPECT_EQ(send.pq_ct.size(), fb::crypto::pq::kMlKem768CtBytes);

    (void)seed_alice;  // alice's seed unused beyond the identity; suppress warning.
}

TEST(Handshake, EmptyPeerPqDegradesToPureX25519) {
    auto alice = ident_from_byte(0x66);
    auto bob   = ident_from_byte(0x77);
    auto x_alice = derive_x25519(alice);
    auto x_bob   = derive_x25519(bob);

    auto hyb = derive_hybrid_send(x_alice,
        std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32),
        std::span<const std::uint8_t>{});
    EXPECT_TRUE(hyb.pq_ct.empty());

    auto pure = derive_shared_secret(x_alice,
        std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32));
    EXPECT_EQ(hyb.shared, pure);
}

TEST(Handshake, EmptyPqCtDegradesToPureX25519OnRecv) {
    auto alice = ident_from_byte(0x88);
    auto bob   = ident_from_byte(0x99);
    auto seed_bob = seed_of_byte(0x99);
    auto x_alice  = derive_x25519(alice);
    auto x_bob    = derive_x25519(bob);
    auto pq_bob   = derive_pq_identity(bob,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed_bob));

    auto pure = derive_shared_secret(x_bob,
        std::span<const std::uint8_t, 32>(x_alice.pub.data(), 32));
    auto recv = derive_hybrid_recv(x_bob,
        std::span<const std::uint8_t, 32>(x_alice.pub.data(), 32),
        std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SecBytes>(
            pq_bob.sec.data(), pq_bob.sec.size()),
        std::span<const std::uint8_t>{});
    EXPECT_EQ(recv, pure);
}

TEST(Handshake, BundleHelperVerifiesBindingSig) {
    auto alice  = ident_from_byte(0xAA);
    auto bob    = ident_from_byte(0xBB);
    auto seed_b = seed_of_byte(0xBB);
    auto x_alice = derive_x25519(alice);
    auto x_bob   = derive_x25519(bob);
    auto pq_bob  = derive_pq_identity(bob,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed_b));

    fb::proto::PreKeyBundle b;
    b.set_identity_pubkey(std::string(
        reinterpret_cast<const char*>(bob.public_key().data()),
        bob.public_key().size()));
    b.set_signed_prekey(std::string(
        reinterpret_cast<const char*>(x_bob.pub.data()), x_bob.pub.size()));
    b.set_pq_pubkey(std::string(
        reinterpret_cast<const char*>(pq_bob.pub.data()), pq_bob.pub.size()));
    b.set_pq_pubkey_sig(std::string(
        reinterpret_cast<const char*>(pq_bob.pubkey_sig.data()),
        pq_bob.pubkey_sig.size()));

    auto hyb = derive_hybrid_send_from_bundle(x_alice,
        std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32), b);
    EXPECT_FALSE(hyb.pq_ct.empty());

    // Flip a bit in the binding sig — helper must refuse rather than
    // silently fall back to X25519 (the wire SAID PQ, so something
    // happened mid-flight; treat as MITM).
    auto tampered = b;
    std::string sig_s = tampered.pq_pubkey_sig();
    sig_s[0] ^= 0x01;
    tampered.set_pq_pubkey_sig(sig_s);
    EXPECT_THROW({
        (void)derive_hybrid_send_from_bundle(x_alice,
            std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32), tampered);
    }, std::runtime_error);
}

TEST(Handshake, BundleWithoutPqGracefullyFallsBack) {
    auto alice  = ident_from_byte(0xC0);
    auto bob    = ident_from_byte(0xC1);
    auto x_alice = derive_x25519(alice);
    auto x_bob   = derive_x25519(bob);

    fb::proto::PreKeyBundle b;
    b.set_identity_pubkey(std::string(
        reinterpret_cast<const char*>(bob.public_key().data()),
        bob.public_key().size()));
    b.set_signed_prekey(std::string(
        reinterpret_cast<const char*>(x_bob.pub.data()), x_bob.pub.size()));
    // No pq_pubkey / no pq_pubkey_sig.

    auto hyb = derive_hybrid_send_from_bundle(x_alice,
        std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32), b);
    EXPECT_TRUE(hyb.pq_ct.empty());

    auto pure = derive_shared_secret(x_alice,
        std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32));
    EXPECT_EQ(hyb.shared, pure);
}
