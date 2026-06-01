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

// ---------------------------------------------------------------------------
// Sealed sender — sender_pubkey hidden from the relay (Signal-style)
// ---------------------------------------------------------------------------

// Bob's identity pubkey, used as the sealed-sender recipient binding.
static std::array<std::uint8_t, 32> recipient_of(std::uint8_t fill) {
    return ident_from_byte(fill).public_key();
}

TEST(Handshake, SealedSenderSigInputIsDomainEnvIdBeTsRecipient) {
    std::array<std::uint8_t, 16> env_id{};
    for (std::size_t i = 0; i < env_id.size(); ++i) {
        env_id[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    auto recipient = recipient_of(0x5A);
    constexpr std::uint64_t ts = 0x0102030405060708ULL;
    auto bytes = sealed_sender_sig_input(
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recipient.data(), recipient.size()));

    // Layout: "FinBit-SealedSender-v1" || env_id(16) || u64_be(8) || recip(32)
    static constexpr char kDomain[] = "FinBit-SealedSender-v1";
    const std::size_t dlen = sizeof(kDomain) - 1;  // exclude NUL
    ASSERT_EQ(bytes.size(), dlen + 16u + 8u + recipient.size());
    for (std::size_t i = 0; i < dlen; ++i) {
        EXPECT_EQ(bytes[i], static_cast<std::uint8_t>(kDomain[i]));
    }
    for (std::size_t i = 0; i < 16; ++i) EXPECT_EQ(bytes[dlen + i], env_id[i]);
    // Big-endian u64 of 0x0102030405060708.
    for (std::size_t i = 0; i < 8; ++i) {
        EXPECT_EQ(bytes[dlen + 16 + i], static_cast<std::uint8_t>(i + 1));
    }
    for (std::size_t i = 0; i < recipient.size(); ++i) {
        EXPECT_EQ(bytes[dlen + 24 + i], recipient[i]);
    }
}

TEST(Handshake, SealedSenderRoundTrip) {
    auto alice = ident_from_byte(0xEE);
    auto recipient = recipient_of(0x10);
    std::array<std::uint8_t, 16> env_id{};
    for (std::size_t i = 0; i < env_id.size(); ++i) {
        env_id[i] = static_cast<std::uint8_t>(i + 1);
    }
    const std::uint64_t ts = 1700000000123ULL;

    auto fields = make_sealed_sender_fields(alice,
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recipient.data(), recipient.size()));
    EXPECT_EQ(fields.pubkey, alice.public_key());

    EXPECT_TRUE(verify_sealed_sender(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            fields.pubkey.data(), fields.pubkey.size()),
        std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>(
            fields.sig.data(), fields.sig.size()),
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recipient.data(), recipient.size())));
}

TEST(Handshake, SealedSenderRejectsTimestampShift) {
    auto alice = ident_from_byte(0xCC);
    auto recipient = recipient_of(0x11);
    std::array<std::uint8_t, 16> env_id{};
    randombytes_buf(env_id.data(), env_id.size());
    const std::uint64_t ts = 1700000000000ULL;
    auto f = make_sealed_sender_fields(alice,
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recipient.data(), recipient.size()));

    // Same sig, different timestamp → MUST fail (relay can't replay
    // an envelope at a different time).
    EXPECT_FALSE(verify_sealed_sender(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            f.pubkey.data(), f.pubkey.size()),
        std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>(
            f.sig.data(), f.sig.size()),
        std::span<const std::uint8_t>(env_id.data(), env_id.size()),
        ts + 1,
        std::span<const std::uint8_t>(recipient.data(), recipient.size())));
}

TEST(Handshake, SealedSenderRejectsEnvelopeIdReplay) {
    auto alice = ident_from_byte(0xDD);
    auto recipient = recipient_of(0x12);
    std::array<std::uint8_t, 16> env_id_a{}, env_id_b{};
    randombytes_buf(env_id_a.data(), env_id_a.size());
    randombytes_buf(env_id_b.data(), env_id_b.size());
    const std::uint64_t ts = 1700000000000ULL;
    auto f = make_sealed_sender_fields(alice,
        std::span<const std::uint8_t>(env_id_a.data(), env_id_a.size()), ts,
        std::span<const std::uint8_t>(recipient.data(), recipient.size()));

    // Reusing the sig against a different envelope id → MUST fail.
    EXPECT_FALSE(verify_sealed_sender(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            f.pubkey.data(), f.pubkey.size()),
        std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>(
            f.sig.data(), f.sig.size()),
        std::span<const std::uint8_t>(env_id_b.data(), env_id_b.size()), ts,
        std::span<const std::uint8_t>(recipient.data(), recipient.size())));
}

// M2 (audit): the seal is bound to its intended recipient. A relay that
// lifts a valid sealed claim onto an envelope routed to a DIFFERENT
// recipient must fail verification under that recipient's own pubkey.
TEST(Handshake, SealedSenderRejectsWrongRecipient) {
    auto alice = ident_from_byte(0xAE);
    auto recip_bob   = recipient_of(0x20);
    auto recip_carol = recipient_of(0x21);
    std::array<std::uint8_t, 16> env_id{};
    randombytes_buf(env_id.data(), env_id.size());
    const std::uint64_t ts = 1700000000777ULL;
    auto f = make_sealed_sender_fields(alice,
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recip_bob.data(), recip_bob.size()));

    // Verifying with Carol's pubkey (the wrong recipient) → MUST fail.
    EXPECT_FALSE(verify_sealed_sender(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            f.pubkey.data(), f.pubkey.size()),
        std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>(
            f.sig.data(), f.sig.size()),
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recip_carol.data(), recip_carol.size())));
    // ...but the intended recipient still verifies.
    EXPECT_TRUE(verify_sealed_sender(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            f.pubkey.data(), f.pubkey.size()),
        std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>(
            f.sig.data(), f.sig.size()),
        std::span<const std::uint8_t>(env_id.data(), env_id.size()), ts,
        std::span<const std::uint8_t>(recip_bob.data(), recip_bob.size())));
}

// ---------------------------------------------------------------------------
// Hybrid signatures — Ed25519 + ML-DSA-65
// ---------------------------------------------------------------------------

#if defined(FB_HAVE_ML_KEM) && FB_HAVE_ML_KEM

TEST(Handshake, PqSigIdentityDeterministicFromIdentitySeed) {
    auto id = ident_from_byte(0xAB);
    auto seed = seed_of_byte(0xAB);
    auto a = derive_pq_sig_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    auto b = derive_pq_sig_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    EXPECT_EQ(a.pub, b.pub);
    EXPECT_EQ(a.sec, b.sec);
    EXPECT_EQ(a.pubkey_sig, b.pubkey_sig);   // Ed25519 deterministic per RFC 8032

    // The binding sig actually verifies over pq.pub by the identity key.
    EXPECT_TRUE(fb::crypto::Identity::verify(
        id.public_key(),
        std::span<const std::uint8_t>(a.pub.data(), a.pub.size()),
        a.pubkey_sig));
}

TEST(Handshake, HybridSignVerifyRoundTrip) {
    auto id = ident_from_byte(0x77);
    auto seed = seed_of_byte(0x77);
    auto pq = derive_pq_sig_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));

    const std::string msg = "FinBit hybrid identity attestation";
    auto sig = hybrid_sign(id, pq,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));

    EXPECT_TRUE(hybrid_verify(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            id.public_key().data(), id.public_key().size()),
        std::span<const std::uint8_t, fb::crypto::pq::kMlDsa65PubBytes>(
            pq.pub.data(), pq.pub.size()),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()),
        sig));
}

TEST(Handshake, HybridVerifyRequiresBothHalves) {
    auto id = ident_from_byte(0x88);
    auto seed = seed_of_byte(0x88);
    auto pq = derive_pq_sig_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    const std::string msg = "double-rooted attestation";
    auto sig = hybrid_sign(id, pq,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));

    auto msg_span = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());

    // Tamper the Ed25519 half — verify must fail (hybrid requires BOTH).
    {
        auto tampered = sig;
        tampered.ed25519[0] ^= 0x01;
        EXPECT_FALSE(hybrid_verify(
            std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
                id.public_key().data(), id.public_key().size()),
            std::span<const std::uint8_t, fb::crypto::pq::kMlDsa65PubBytes>(
                pq.pub.data(), pq.pub.size()),
            msg_span, tampered));
    }
    // Tamper the ML-DSA half — verify must fail (hybrid requires BOTH).
    {
        auto tampered = sig;
        tampered.pq[100] ^= 0x80;
        EXPECT_FALSE(hybrid_verify(
            std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
                id.public_key().data(), id.public_key().size()),
            std::span<const std::uint8_t, fb::crypto::pq::kMlDsa65PubBytes>(
                pq.pub.data(), pq.pub.size()),
            msg_span, tampered));
    }
}

// ---- PreKeyBundle PQ-sig wiring -------------------------------------------

namespace {

// Construct a minimally-valid PreKeyBundle with both PQ-KEM + PQ-sig fields
// populated for `id`. The other fields (signed_prekey, signed_prekey_sig)
// get nonzero placeholders so the wire-format invariants hold.
fb::proto::PreKeyBundle make_full_bundle(const fb::crypto::Identity& id,
                                         std::span<const std::uint8_t,
                                                   fb::crypto::kIdentitySeedBytes> seed) {
    fb::proto::PreKeyBundle b;
    b.set_identity_pubkey(std::string(
        reinterpret_cast<const char*>(id.public_key().data()),
        id.public_key().size()));
    // Phase-0 placeholder SPK + sig (real binding done by the actual SPK
    // signature; we only need the bytes to exist for PQ-sig coverage).
    std::array<std::uint8_t, 32> spk{};
    for (std::size_t i = 0; i < spk.size(); ++i) spk[i] = i + 1;
    b.set_signed_prekey(std::string(spk.begin(), spk.end()));
    auto spk_ed_sig = id.sign(
        std::span<const std::uint8_t>(spk.data(), spk.size()));
    b.set_signed_prekey_sig(std::string(
        spk_ed_sig.begin(), spk_ed_sig.end()));

    auto pq_id = fb::handshake::derive_pq_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    b.set_pq_pubkey(std::string(pq_id.pub.begin(), pq_id.pub.end()));
    b.set_pq_pubkey_sig(std::string(
        pq_id.pubkey_sig.begin(), pq_id.pubkey_sig.end()));

    auto pq_sig = fb::handshake::derive_pq_sig_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    fb::handshake::add_pq_sig_fields_to_bundle(b, id, pq_sig);
    return b;
}

}  // namespace

TEST(Handshake, BundlePqSigsRoundTrip) {
    auto id = ident_from_byte(0x44);
    auto seed = seed_of_byte(0x44);
    auto b = make_full_bundle(id, seed);
    EXPECT_EQ(b.pq_sig_pubkey().size(), fb::crypto::pq::kMlDsa65PubBytes);
    EXPECT_EQ(b.pq_sig_pubkey_sig().size(), fb::crypto::kIdentitySigBytes);
    EXPECT_EQ(b.signed_prekey_sig_pq().size(), fb::crypto::pq::kMlDsa65SigBytes);
    EXPECT_EQ(b.pq_pubkey_sig_pq().size(), fb::crypto::pq::kMlDsa65SigBytes);
    EXPECT_TRUE(verify_bundle_pq_sigs(b));
}

TEST(Handshake, BundleWithoutPqSigsPassesAsLegacy) {
    auto id = ident_from_byte(0x55);
    fb::proto::PreKeyBundle b;
    b.set_identity_pubkey(std::string(
        reinterpret_cast<const char*>(id.public_key().data()),
        id.public_key().size()));
    // No PQ-sig fields → legacy publisher → must pass.
    EXPECT_TRUE(verify_bundle_pq_sigs(b));
}

TEST(Handshake, BundlePqSigsRejectStrippedSubset) {
    auto id = ident_from_byte(0x66);
    auto seed = seed_of_byte(0x66);
    auto b = make_full_bundle(id, seed);
    // Strip pq_sig_pubkey_sig but leave the other PQ-sig fields — MITM
    // partial-strip should be REFUSED (not silently downgraded).
    b.clear_pq_sig_pubkey_sig();
    EXPECT_FALSE(verify_bundle_pq_sigs(b));
}

TEST(Handshake, BundlePqSigsRejectTamperedSpkSigPq) {
    auto id = ident_from_byte(0x77);
    auto seed = seed_of_byte(0x77);
    auto b = make_full_bundle(id, seed);
    auto s = b.signed_prekey_sig_pq();
    s[100] ^= 0x80;
    b.set_signed_prekey_sig_pq(s);
    EXPECT_FALSE(verify_bundle_pq_sigs(b));
}

TEST(Handshake, BundlePqSigsRejectTamperedPqPubkeySigPq) {
    auto id = ident_from_byte(0x88);
    auto seed = seed_of_byte(0x88);
    auto b = make_full_bundle(id, seed);
    auto s = b.pq_pubkey_sig_pq();
    s[42] ^= 0x01;
    b.set_pq_pubkey_sig_pq(s);
    EXPECT_FALSE(verify_bundle_pq_sigs(b));
}

TEST(Handshake, BundlePqSigsRejectSwappedPqSigPubkey) {
    auto id = ident_from_byte(0x99);
    auto seed_a = seed_of_byte(0x99);
    auto seed_b = seed_of_byte(0xAA);
    auto bundle = make_full_bundle(id, seed_a);
    // MITM swaps in an unrelated PQ-sig pubkey + tries to keep going.
    // Without re-signing the binding, the pq_sig_pubkey_sig fails first.
    auto wrong = fb::handshake::derive_pq_sig_identity(
        ident_from_byte(0xBB),   // a different identity entirely
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed_b));
    bundle.set_pq_sig_pubkey(std::string(
        wrong.pub.begin(), wrong.pub.end()));
    EXPECT_FALSE(verify_bundle_pq_sigs(bundle));
}

// PQ CRITICAL-1 (audit): a MITM that strips the ML-KEM pq_pubkey (and its
// two binding sigs) while leaving the still-valid PQ-sig identity fields
// intact must be REFUSED. Otherwise the session silently downgrades to
// classical-only X25519, defeating harvest-now-decrypt-later against an
// ordinary relay. Nothing else in the bundle commits to the KEM key's
// presence, so verify_bundle_pq_sigs must mandate it.
TEST(Handshake, BundlePqSigsRejectStrippedKem) {
    auto id = ident_from_byte(0x5C);
    auto seed = seed_of_byte(0x5C);
    auto b = make_full_bundle(id, seed);
    ASSERT_TRUE(verify_bundle_pq_sigs(b));   // intact bundle verifies

    // Strip the KEM half: pq_pubkey + its Ed25519 binding + its ML-DSA
    // binding, leaving the (genuine) PQ-sig identity fields untouched.
    b.clear_pq_pubkey();
    b.clear_pq_pubkey_sig();
    b.clear_pq_pubkey_sig_pq();
    EXPECT_FALSE(verify_bundle_pq_sigs(b));

    // The bundle-driven send path must THROW rather than silently fall back
    // to pure X25519.
    auto alice   = ident_from_byte(0x5D);
    auto x_alice = derive_x25519(alice);
    auto x_bob   = derive_x25519(id);
    EXPECT_THROW({
        (void)derive_hybrid_send_from_bundle(x_alice,
            std::span<const std::uint8_t, 32>(x_bob.pub.data(), 32), b);
    }, std::runtime_error);
}

TEST(Handshake, HybridVerifyRejectsWrongMessage) {
    auto id = ident_from_byte(0x99);
    auto seed = seed_of_byte(0x99);
    auto pq = derive_pq_sig_identity(id,
        std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes>(seed));
    const std::string original = "I, Alice, do hereby...";
    const std::string substituted = "I, Alice, do something else...";
    auto sig = hybrid_sign(id, pq,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(original.data()),
            original.size()));
    EXPECT_FALSE(hybrid_verify(
        std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>(
            id.public_key().data(), id.public_key().size()),
        std::span<const std::uint8_t, fb::crypto::pq::kMlDsa65PubBytes>(
            pq.pub.data(), pq.pub.size()),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(substituted.data()),
            substituted.size()),
        sig));
}

#endif  // FB_HAVE_ML_KEM

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

// TOFU PQ-capability downgrade policy (audit residual). verify_bundle_pq_sigs
// catches a PARTIAL strip but is blind to a FULL strip (all PQ fields gone →
// legacy-looking bundle). The cross-session pin closes it: once a peer is
// pinned PQ-capable, a later PQ-less bundle from the same identity is a
// downgrade and must be refused.
TEST(Handshake, PqCapabilityDowngradeTruthTable) {
    using fb::handshake::is_pq_capability_downgrade;
    // Never pinned PQ for this peer → nothing to violate, any bundle is fine.
    EXPECT_FALSE(is_pq_capability_downgrade(/*prev=*/false, /*now=*/false));
    EXPECT_FALSE(is_pq_capability_downgrade(/*prev=*/false, /*now=*/true));
    // Pinned PQ-capable and still advertising PQ → fine.
    EXPECT_FALSE(is_pq_capability_downgrade(/*prev=*/true,  /*now=*/true));
    // Pinned PQ-capable but PQ now stripped → DOWNGRADE, refuse.
    EXPECT_TRUE (is_pq_capability_downgrade(/*prev=*/true,  /*now=*/false));
}
