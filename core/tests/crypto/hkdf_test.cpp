// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HKDF-SHA256 KAT against RFC 5869 Test Cases 1 + 2 + 3. The PRK and OKM
// values are taken verbatim from the appendix; if our implementation
// produces different bytes the test fails — that's the whole point.

#include "fb/crypto/hkdf.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> hex(const char* s) {
    std::vector<std::uint8_t> out;
    while (*s) {
        unsigned v = 0;
        char c = *s++;
        if (c == ' ') continue;
        v = (c <= '9' ? c - '0' : (c | 32) - 'a' + 10) << 4;
        c = *s++;
        v |= (c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return out;
}

}  // namespace

// RFC 5869 Test Case 1 (basic): IKM=22B, salt=13B, info=10B, L=42.
TEST(HkdfSha256Kat, Rfc5869Tc1) {
    const auto ikm  = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto salt = hex("000102030405060708090a0b0c");
    const auto info = hex("f0f1f2f3f4f5f6f7f8f9");
    const auto expected_prk = hex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5");
    const auto expected_okm = hex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865");

    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(salt.data(), salt.size()),
        std::span<const std::uint8_t>(ikm.data(), ikm.size()));
    EXPECT_EQ(std::vector<std::uint8_t>(prk.begin(), prk.end()), expected_prk);

    auto okm = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(info.data(), info.size()), 42);
    EXPECT_EQ(okm, expected_okm);
}

// RFC 5869 Test Case 2 (longer inputs): IKM=80B, salt=80B, info=80B, L=82.
TEST(HkdfSha256Kat, Rfc5869Tc2) {
    const auto ikm = hex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f");
    const auto salt = hex(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    const auto info = hex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const auto expected_okm = hex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87");

    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(salt.data(), salt.size()),
        std::span<const std::uint8_t>(ikm.data(), ikm.size()));
    auto okm = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(info.data(), info.size()), 82);
    EXPECT_EQ(okm, expected_okm);
}

// RFC 5869 Test Case 3 (zero-length salt + info, L=42).
TEST(HkdfSha256Kat, Rfc5869Tc3) {
    const auto ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto expected_okm = hex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8");

    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(ikm.data(), ikm.size()));
    auto okm = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(), 42);
    EXPECT_EQ(okm, expected_okm);
}

// Out-of-range L is rejected at the API boundary.
TEST(HkdfSha256, ExpandRejectsOutOfRangeLen) {
    fb::crypto::HkdfPrk prk{};
    EXPECT_THROW(fb::crypto::hkdf_expand(prk, std::span<const std::uint8_t>(), 0),
                 std::invalid_argument);
    EXPECT_THROW(fb::crypto::hkdf_expand(prk, std::span<const std::uint8_t>(), 8161),
                 std::invalid_argument);
    // Boundaries should be fine.
    EXPECT_NO_THROW(fb::crypto::hkdf_expand(prk, std::span<const std::uint8_t>(), 1));
    EXPECT_NO_THROW(fb::crypto::hkdf_expand(prk, std::span<const std::uint8_t>(), 8160));
}
