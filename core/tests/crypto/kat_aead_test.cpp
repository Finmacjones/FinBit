// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// AES-256-GCM Known-Answer Test
//
// Vector: "Test Case 16" from McGrew & Viega's GCM specification (also present
// in NIST CAVP gcmEncryptExtIV256.rsp). 96-bit IV, 128-bit tag, 60-byte PT,
// 20-byte AAD, 256-bit key.
//
// Source:
//   https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/gcm/gcm-spec.pdf
//   §A.6 Test Case 16
//
// libsodium's combined-mode AEAD output is `ciphertext || tag`, so we expect
// `kExpectedCiphertext || kExpectedTag` from aead_encrypt.
// =============================================================================

#include "fb/crypto/aead.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

constexpr std::array<std::uint8_t, 32> kKey = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
};

constexpr std::array<std::uint8_t, 12> kIv = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
};

constexpr std::array<std::uint8_t, 60> kPlaintext = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
};

constexpr std::array<std::uint8_t, 20> kAad = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
    0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
};

constexpr std::array<std::uint8_t, 60> kExpectedCiphertext = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
};

constexpr std::array<std::uint8_t, 16> kExpectedTag = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
    0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
};

template <std::size_t N>
std::span<const std::uint8_t> as_span(const std::array<std::uint8_t, N>& a) {
    return std::span<const std::uint8_t>(a.data(), a.size());
}

}  // namespace

TEST(Aes256GcmKat, McgrewViegaTestCase16_HardwareAvailable) {
    // The test vector is meaningless on machines without AES-NI / ARMv8 crypto,
    // and libsodium will refuse to encrypt. Skip explicitly so CI on bare ARM
    // (e.g. an old Raspberry Pi runner) reports skipped rather than failed.
    if (!fb::crypto::aes256gcm_hw_available()) {
        GTEST_SKIP() << "AES-256-GCM not hardware-accelerated on this CPU; "
                        "fallback path not yet implemented (Phase 0).";
    }

    fb::crypto::AeadKey key{};
    fb::crypto::AeadNonce nonce{};
    std::copy(kKey.begin(), kKey.end(), key.begin());
    std::copy(kIv.begin(), kIv.end(), nonce.begin());

    const auto out = fb::crypto::aead_encrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce,
                                              as_span(kPlaintext), as_span(kAad));

    ASSERT_EQ(out.size(), kExpectedCiphertext.size() + kExpectedTag.size());

    EXPECT_TRUE(std::equal(kExpectedCiphertext.begin(), kExpectedCiphertext.end(), out.begin()))
        << "ciphertext mismatch against NIST/McGrew Test Case 16";
    EXPECT_TRUE(std::equal(kExpectedTag.begin(), kExpectedTag.end(),
                           out.begin() + kExpectedCiphertext.size()))
        << "tag mismatch against NIST/McGrew Test Case 16";

    const auto rt = fb::crypto::aead_decrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce, out,
                                             as_span(kAad));
    ASSERT_TRUE(rt.has_value()) << "round-trip decrypt failed for valid ciphertext";
    EXPECT_TRUE(std::equal(kPlaintext.begin(), kPlaintext.end(), rt->begin()));
}

TEST(Aes256GcmKat, TamperedTagFails) {
    if (!fb::crypto::aes256gcm_hw_available()) {
        GTEST_SKIP();
    }
    fb::crypto::AeadKey key{};
    fb::crypto::AeadNonce nonce{};
    std::copy(kKey.begin(), kKey.end(), key.begin());
    std::copy(kIv.begin(), kIv.end(), nonce.begin());

    auto ct = fb::crypto::aead_encrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce,
                                       as_span(kPlaintext), as_span(kAad));
    // Flip one bit in the tag (last 16 bytes).
    ct.back() ^= 0x01;
    EXPECT_FALSE(fb::crypto::aead_decrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce, ct,
                                          as_span(kAad))
                     .has_value());
}

TEST(Aes256GcmKat, TamperedAadFails) {
    if (!fb::crypto::aes256gcm_hw_available()) {
        GTEST_SKIP();
    }
    fb::crypto::AeadKey key{};
    fb::crypto::AeadNonce nonce{};
    std::copy(kKey.begin(), kKey.end(), key.begin());
    std::copy(kIv.begin(), kIv.end(), nonce.begin());

    const auto ct = fb::crypto::aead_encrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce,
                                             as_span(kPlaintext), as_span(kAad));
    auto bad_aad = std::vector<std::uint8_t>(kAad.begin(), kAad.end());
    bad_aad.front() ^= 0x80;
    EXPECT_FALSE(fb::crypto::aead_decrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce, ct,
                                          std::span<const std::uint8_t>(bad_aad))
                     .has_value());
}

TEST(Aes256GcmKat, RejectsUnimplementedAlgorithmInAesEntryPoint) {
    fb::crypto::AeadKey key{};
    fb::crypto::AeadNonce nonce{};
    // The aead_encrypt entry point is AES-only; XChaCha goes through
    // xchacha20_encrypt(). Asking aead_encrypt for kXChaCha20Poly1305
    // should still throw — that's the discriminator's job at this seam.
    auto attempt = [&] {
        const auto out = fb::crypto::aead_encrypt(fb::crypto::AeadAlg::kXChaCha20Poly1305, key,
                                                  nonce, as_span(kPlaintext), as_span(kAad));
        (void)out;
    };
    EXPECT_THROW(attempt(), std::invalid_argument);
}

// XChaCha20-Poly1305 round-trip + tamper-reject. No fixed published KAT
// because there isn't a single canonical XChaCha20-IETF vector across
// libsodium / RFC drafts; the round-trip + cross-implementation property
// (libsodium's symmetric encrypt/decrypt agree) is what we test.
TEST(XChaChaAead, RoundTripAndTamper) {
    fb::crypto::AeadKey key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(0xC0 ^ i);
    auto nonce = fb::crypto::random_xchacha_nonce();
    const std::vector<std::uint8_t> pt(kPlaintext.begin(), kPlaintext.end());
    const std::vector<std::uint8_t> aad(kAad.begin(), kAad.end());

    auto ct = fb::crypto::xchacha20_encrypt(
        key, nonce, std::span<const std::uint8_t>(pt.data(), pt.size()),
        std::span<const std::uint8_t>(aad.data(), aad.size()));
    ASSERT_EQ(ct.size(), pt.size() + 16u);

    auto rt = fb::crypto::xchacha20_decrypt(
        key, nonce, std::span<const std::uint8_t>(ct.data(), ct.size()),
        std::span<const std::uint8_t>(aad.data(), aad.size()));
    ASSERT_TRUE(rt.has_value());
    EXPECT_EQ(*rt, pt);

    // Tampered tag.
    auto bad = ct;
    bad.back() ^= 0x01;
    EXPECT_FALSE(fb::crypto::xchacha20_decrypt(
                     key, nonce, std::span<const std::uint8_t>(bad.data(), bad.size()),
                     std::span<const std::uint8_t>(aad.data(), aad.size()))
                     .has_value());

    // Tampered AAD.
    auto bad_aad = aad;
    bad_aad.front() ^= 0x80;
    EXPECT_FALSE(fb::crypto::xchacha20_decrypt(
                     key, nonce, std::span<const std::uint8_t>(ct.data(), ct.size()),
                     std::span<const std::uint8_t>(bad_aad.data(), bad_aad.size()))
                     .has_value());
}

TEST(XChaChaAead, NoHardwareGate) {
    // Unlike AES-256-GCM, XChaCha20 is portable software-only — must work
    // on every CPU, including where AES-NI is unavailable (and in WASM).
    EXPECT_TRUE(fb::crypto::xchacha20poly1305_available());
}
