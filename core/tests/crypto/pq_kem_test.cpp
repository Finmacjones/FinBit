// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/pq_kem.hpp"
#include "fb/crypto/hybrid_kem.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

using namespace fb::crypto;

// ===========================================================================
// ML-KEM-768 module
// ===========================================================================

TEST(PqKem, AvailabilityMatchesBuildFlag) {
#if defined(FB_HAVE_ML_KEM) && FB_HAVE_ML_KEM
    EXPECT_TRUE(pq::ml_kem_768_available());
#else
    EXPECT_FALSE(pq::ml_kem_768_available());
#endif
}

#if defined(FB_HAVE_ML_KEM) && FB_HAVE_ML_KEM

TEST(PqKem, KeygenProducesCorrectlySizedMaterial) {
    auto kp = pq::keygen_ml_kem_768();
    EXPECT_EQ(kp.pub.size(), pq::kMlKem768PubBytes);
    EXPECT_EQ(kp.sec.size(), pq::kMlKem768SecBytes);

    // Keys are not all-zero (sanity — RNG worked).
    bool any_pub_nz = false;
    for (auto b : kp.pub) { if (b) { any_pub_nz = true; break; } }
    bool any_sec_nz = false;
    for (auto b : kp.sec) { if (b) { any_sec_nz = true; break; } }
    EXPECT_TRUE(any_pub_nz);
    EXPECT_TRUE(any_sec_nz);
}

TEST(PqKem, EncapDecapRoundTrip) {
    auto kp = pq::keygen_ml_kem_768();

    auto enc = pq::encap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768PubBytes>(kp.pub));
    auto ss_recovered = pq::decap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768CtBytes>(enc.ct),
        std::span<const std::uint8_t, pq::kMlKem768SecBytes>(kp.sec));

    EXPECT_EQ(enc.ss, ss_recovered);
}

TEST(PqKem, EncapIsProbabilistic) {
    // FIPS-203 encap takes fresh randomness — two encaps against the same
    // pubkey MUST yield different ciphertexts (and different secrets).
    auto kp = pq::keygen_ml_kem_768();
    auto e1 = pq::encap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768PubBytes>(kp.pub));
    auto e2 = pq::encap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768PubBytes>(kp.pub));
    EXPECT_NE(e1.ct, e2.ct);
    EXPECT_NE(e1.ss, e2.ss);
}

TEST(PqKem, SeededKeygenIsDeterministic) {
    std::array<std::uint8_t, pq::kMlKem768SeedBytes> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    auto a = pq::keygen_ml_kem_768_from_seed(
        std::span<const std::uint8_t, pq::kMlKem768SeedBytes>(seed));
    auto b = pq::keygen_ml_kem_768_from_seed(
        std::span<const std::uint8_t, pq::kMlKem768SeedBytes>(seed));
    EXPECT_EQ(a.pub, b.pub);
    EXPECT_EQ(a.sec, b.sec);

    seed[0] ^= 0xFF;
    auto c = pq::keygen_ml_kem_768_from_seed(
        std::span<const std::uint8_t, pq::kMlKem768SeedBytes>(seed));
    EXPECT_NE(a.pub, c.pub);
    EXPECT_NE(a.sec, c.sec);
}

TEST(PqKem, SeededKeyEncapDecapRoundTrip) {
    // The same seed must produce a working keypair (catches a future
    // upstream change that silently turns seeded keygen into "ignore seed").
    std::array<std::uint8_t, pq::kMlKem768SeedBytes> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(0x80 ^ i);
    auto kp = pq::keygen_ml_kem_768_from_seed(
        std::span<const std::uint8_t, pq::kMlKem768SeedBytes>(seed));
    auto enc = pq::encap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768PubBytes>(kp.pub));
    auto ss = pq::decap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768CtBytes>(enc.ct),
        std::span<const std::uint8_t, pq::kMlKem768SecBytes>(kp.sec));
    EXPECT_EQ(enc.ss, ss);
}

TEST(PqKem, IndependentKeypairsDoNotInteract) {
    auto a = pq::keygen_ml_kem_768();
    auto b = pq::keygen_ml_kem_768();
    auto enc_for_a = pq::encap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768PubBytes>(a.pub));
    // Decapsulating A's ciphertext with B's secret is IND-CCA2 implicit-
    // rejection: it returns SOME pseudorandom secret, not the one A's
    // encapsulator kept. The point is they MUST differ — otherwise B
    // could read traffic destined for A.
    auto wrong = pq::decap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768CtBytes>(enc_for_a.ct),
        std::span<const std::uint8_t, pq::kMlKem768SecBytes>(b.sec));
    EXPECT_NE(enc_for_a.ss, wrong);
}

// ===========================================================================
// Hybrid combiner
// ===========================================================================

TEST(HybridKem, CombineIsDeterministicForFixedInputs) {
    std::array<std::uint8_t, 32> x{};
    std::array<std::uint8_t, 32> p{};
    for (std::size_t i = 0; i < 32; ++i) { x[i] = static_cast<std::uint8_t>(i); }
    for (std::size_t i = 0; i < 32; ++i) { p[i] = static_cast<std::uint8_t>(0xFF - i); }

    auto h1 = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(x),
                                              std::span<const std::uint8_t, 32>(p));
    auto h2 = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(x),
                                              std::span<const std::uint8_t, 32>(p));
    EXPECT_EQ(h1, h2);
    // Sanity: not the trivial XOR / not just one of the inputs.
    EXPECT_NE(h1, x);
    EXPECT_NE(h1, p);
}

TEST(HybridKem, SwappingHalvesChangesOutput) {
    // Order matters: ss_x25519 || ss_mlkem ≠ ss_mlkem || ss_x25519.
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};
    for (std::size_t i = 0; i < 32; ++i) { a[i] = static_cast<std::uint8_t>(i); }
    for (std::size_t i = 0; i < 32; ++i) { b[i] = static_cast<std::uint8_t>(2 * i + 1); }
    auto ab = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(a),
                                              std::span<const std::uint8_t, 32>(b));
    auto ba = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(b),
                                              std::span<const std::uint8_t, 32>(a));
    EXPECT_NE(ab, ba);
}

TEST(HybridKem, ChangingOneByteChangesOutput) {
    // Avalanche sanity — flipping a single bit in either half rerolls the
    // entire output, otherwise the combiner has lost a property HKDF gives us.
    std::array<std::uint8_t, 32> x{};
    std::array<std::uint8_t, 32> p{};
    auto base = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(x),
                                                std::span<const std::uint8_t, 32>(p));

    x[7] ^= 0x01;
    auto flip_x = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(x),
                                                  std::span<const std::uint8_t, 32>(p));
    EXPECT_NE(base, flip_x);

    x[7] ^= 0x01;  // restore
    p[19] ^= 0x80;
    auto flip_p = hybrid::combine_x25519_mlkem768(std::span<const std::uint8_t, 32>(x),
                                                  std::span<const std::uint8_t, 32>(p));
    EXPECT_NE(base, flip_p);
}

#if defined(FB_HAVE_ML_KEM) && FB_HAVE_ML_KEM
TEST(HybridKem, EndToEndPqxdhStyleMatch) {
    // Alice → Bob session setup with hybrid X25519+ML-KEM.
    //
    // Bob publishes (X25519_pub_B, PQ_pub_B).
    // Alice does ECDH(X25519_priv_A, X25519_pub_B) → ss_x_A
    //       and ML-KEM-encap(PQ_pub_B)             → (ct, ss_pq_A)
    //       sends X25519_pub_A + ct to Bob.
    // Bob does ECDH(X25519_priv_B, X25519_pub_A)   → ss_x_B  (== ss_x_A)
    //       and ML-KEM-decap(PQ_priv_B, ct)        → ss_pq_B (== ss_pq_A)
    // Both derive the SAME hybrid root.
    //
    // (Stand in for X25519 with a known matching pair of bytes — proves the
    // hybrid is wired correctly without re-testing libsodium's ECDH.)
    std::array<std::uint8_t, 32> ss_x{};
    for (std::size_t i = 0; i < 32; ++i) { ss_x[i] = static_cast<std::uint8_t>(0xAA ^ i); }

    auto bob = pq::keygen_ml_kem_768();
    auto alice_encap = pq::encap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768PubBytes>(bob.pub));
    auto bob_decap = pq::decap_ml_kem_768(
        std::span<const std::uint8_t, pq::kMlKem768CtBytes>(alice_encap.ct),
        std::span<const std::uint8_t, pq::kMlKem768SecBytes>(bob.sec));

    auto alice_root = hybrid::combine_x25519_mlkem768(
        std::span<const std::uint8_t, 32>(ss_x),
        std::span<const std::uint8_t, 32>(alice_encap.ss));
    auto bob_root = hybrid::combine_x25519_mlkem768(
        std::span<const std::uint8_t, 32>(ss_x),
        std::span<const std::uint8_t, 32>(bob_decap));

    EXPECT_EQ(alice_root, bob_root);
}
#endif

// ===========================================================================
// ML-DSA-65 (FIPS-204) — post-quantum signature
// ===========================================================================

TEST(PqSig, AvailabilityTracksMlKemBuildFlag) {
    EXPECT_EQ(pq::ml_dsa_65_available(), pq::ml_kem_768_available());
}

TEST(PqSig, KeygenSizes) {
    auto kp = pq::keygen_ml_dsa_65();
    EXPECT_EQ(kp.pub.size(), pq::kMlDsa65PubBytes);
    EXPECT_EQ(kp.sec.size(), pq::kMlDsa65SecBytes);
    bool any_pub_nz = false, any_sec_nz = false;
    for (auto b : kp.pub) if (b) { any_pub_nz = true; break; }
    for (auto b : kp.sec) if (b) { any_sec_nz = true; break; }
    EXPECT_TRUE(any_pub_nz);
    EXPECT_TRUE(any_sec_nz);
}

TEST(PqSig, SeededKeygenIsDeterministic) {
    std::array<std::uint8_t, pq::kMlDsa65SeedBytes> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(0xC0 ^ i);
    }
    auto a = pq::keygen_ml_dsa_65_from_seed(
        std::span<const std::uint8_t, pq::kMlDsa65SeedBytes>(seed));
    auto b = pq::keygen_ml_dsa_65_from_seed(
        std::span<const std::uint8_t, pq::kMlDsa65SeedBytes>(seed));
    EXPECT_EQ(a.pub, b.pub);
    EXPECT_EQ(a.sec, b.sec);

    seed[0] ^= 0xFF;
    auto c = pq::keygen_ml_dsa_65_from_seed(
        std::span<const std::uint8_t, pq::kMlDsa65SeedBytes>(seed));
    EXPECT_NE(a.pub, c.pub);
}

TEST(PqSig, SignVerifyRoundTrip) {
    auto kp = pq::keygen_ml_dsa_65();
    const std::string msg = "FinBit hybrid signature test vector";
    auto sig = pq::sign_ml_dsa_65(
        std::span<const std::uint8_t, pq::kMlDsa65SecBytes>(kp.sec),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
    EXPECT_EQ(sig.size(), pq::kMlDsa65SigBytes);
    EXPECT_TRUE(pq::verify_ml_dsa_65(
        std::span<const std::uint8_t, pq::kMlDsa65PubBytes>(kp.pub),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()),
        std::span<const std::uint8_t, pq::kMlDsa65SigBytes>(sig)));
}

TEST(PqSig, VerifyRejectsTamperedMessage) {
    auto kp = pq::keygen_ml_dsa_65();
    const std::string msg  = "original";
    const std::string msg2 = "tampered";
    auto sig = pq::sign_ml_dsa_65(
        std::span<const std::uint8_t, pq::kMlDsa65SecBytes>(kp.sec),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
    EXPECT_FALSE(pq::verify_ml_dsa_65(
        std::span<const std::uint8_t, pq::kMlDsa65PubBytes>(kp.pub),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg2.data()), msg2.size()),
        std::span<const std::uint8_t, pq::kMlDsa65SigBytes>(sig)));
}

TEST(PqSig, VerifyRejectsWrongPublicKey) {
    auto kp_a = pq::keygen_ml_dsa_65();
    auto kp_b = pq::keygen_ml_dsa_65();
    const std::string msg = "signed by A";
    auto sig = pq::sign_ml_dsa_65(
        std::span<const std::uint8_t, pq::kMlDsa65SecBytes>(kp_a.sec),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
    EXPECT_FALSE(pq::verify_ml_dsa_65(
        std::span<const std::uint8_t, pq::kMlDsa65PubBytes>(kp_b.pub),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()),
        std::span<const std::uint8_t, pq::kMlDsa65SigBytes>(sig)));
}

#endif  // FB_HAVE_ML_KEM
