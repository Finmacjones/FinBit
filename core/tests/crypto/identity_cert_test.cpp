// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// identity_cert gtests.
//
// Coverage (FB_HAVE_OPENSSL=1):
//   - generate_identity_cert produces a valid PEM cert + key
//   - extract_pubkey_from_cert_pem round trips with the original seed's
//     derived Ed25519 public key
//   - two distinct seeds → two distinct embedded pubkeys
//   - extract on garbage / non-Ed25519 input returns nullopt
// =============================================================================

#include "fb/crypto/identity_cert.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>

#if FB_HAVE_OPENSSL

namespace {

// Derive the Ed25519 public key from a 32-byte seed (matches the
// derivation OpenSSL does inside EVP_PKEY_new_raw_private_key, so we
// can compare the cert's embedded pubkey against this expected value).
std::array<std::uint8_t, 32> pub_from_seed(
    std::span<const std::uint8_t, 32> seed) {
    if (sodium_init() < 0) std::abort();
    std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> sec{};
    crypto_sign_seed_keypair(pub.data(), sec.data(), seed.data());
    return pub;
}

}  // namespace

TEST(IdentityCert, GenerateProducesNonEmptyPem) {
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);
    auto ck = fb::crypto::generate_identity_cert(
        std::span<const std::uint8_t, 32>(seed));
    EXPECT_NE(ck.cert_pem.find("-----BEGIN CERTIFICATE-----"),
              std::string::npos);
    EXPECT_NE(ck.cert_pem.find("-----END CERTIFICATE-----"),
              std::string::npos);
    EXPECT_NE(ck.key_pem.find("-----BEGIN PRIVATE KEY-----"),
              std::string::npos);
}

TEST(IdentityCert, EmbeddedPubkeyMatchesSeedDerivation) {
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = 0x42;
    auto ck = fb::crypto::generate_identity_cert(
        std::span<const std::uint8_t, 32>(seed));
    auto extracted = fb::crypto::extract_pubkey_from_cert_pem(ck.cert_pem);
    ASSERT_TRUE(extracted.has_value());
    auto expected = pub_from_seed(std::span<const std::uint8_t, 32>(seed));
    EXPECT_TRUE(std::equal(extracted->begin(), extracted->end(),
                           expected.begin()));
}

TEST(IdentityCert, DistinctSeedsProduceDistinctPubkeys) {
    std::array<std::uint8_t, 32> s1{}; s1[0] = 1;
    std::array<std::uint8_t, 32> s2{}; s2[0] = 2;
    auto ck1 = fb::crypto::generate_identity_cert(
        std::span<const std::uint8_t, 32>(s1));
    auto ck2 = fb::crypto::generate_identity_cert(
        std::span<const std::uint8_t, 32>(s2));
    auto p1 = fb::crypto::extract_pubkey_from_cert_pem(ck1.cert_pem);
    auto p2 = fb::crypto::extract_pubkey_from_cert_pem(ck2.cert_pem);
    ASSERT_TRUE(p1 && p2);
    EXPECT_FALSE(std::equal(p1->begin(), p1->end(), p2->begin()));
}

TEST(IdentityCert, ExtractFromGarbageReturnsNullopt) {
    EXPECT_FALSE(fb::crypto::extract_pubkey_from_cert_pem(
        "not a pem file").has_value());
    EXPECT_FALSE(fb::crypto::extract_pubkey_from_cert_pem(
        "").has_value());
}

#else  // FB_HAVE_OPENSSL == 0

TEST(IdentityCert, StubBuildThrows) {
    std::array<std::uint8_t, 32> seed{};
    EXPECT_THROW({
        (void)fb::crypto::generate_identity_cert(
            std::span<const std::uint8_t, 32>(seed));
    }, std::runtime_error);
}

#endif
