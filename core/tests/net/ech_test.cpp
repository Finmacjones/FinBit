// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tier-4 ECH config handling: ECHConfigList framing validation, base64
// decode, and the FinBit TXT `ech=` token parser. (The encryption
// itself is the TLS stack's job and is gated on FB_HAVE_ECH — see
// docs/censorship-resistance.md.)

#include "fb/net/ech.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <sodium.h>
#include <string>
#include <vector>

namespace ech = fb::net::ech;

namespace {

// Build a minimal-but-well-framed ECHConfigList containing `n` configs,
// each with a `body_len`-byte (zeroed) contents block. Layout:
//   uint16 outer_len, then n * { uint16 version, uint16 length, body }.
std::vector<std::uint8_t> make_ech_config_list(int n, std::size_t body_len) {
    std::vector<std::uint8_t> inner;
    for (int i = 0; i < n; ++i) {
        inner.push_back(0xfe); inner.push_back(0x0d);            // version
        inner.push_back(static_cast<std::uint8_t>((body_len >> 8) & 0xff));
        inner.push_back(static_cast<std::uint8_t>(body_len & 0xff));
        inner.insert(inner.end(), body_len, 0x00);              // contents
    }
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>((inner.size() >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(inner.size() & 0xff));
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

std::string b64(const std::vector<std::uint8_t>& bytes) {
    std::string out(sodium_base64_ENCODED_LEN(
                        bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

}  // namespace

TEST(EchConfigList, AcceptsWellFramedSingleConfig) {
    EXPECT_TRUE(ech::ech_config_list_looks_valid(make_ech_config_list(1, 32)));
}

TEST(EchConfigList, AcceptsMultipleConfigs) {
    EXPECT_TRUE(ech::ech_config_list_looks_valid(make_ech_config_list(3, 40)));
}

TEST(EchConfigList, RejectsEmptyAndTooShort) {
    EXPECT_FALSE(ech::ech_config_list_looks_valid({}));
    EXPECT_FALSE(ech::ech_config_list_looks_valid({0x00}));
    EXPECT_FALSE(ech::ech_config_list_looks_valid({0x00, 0x00}));  // zero configs
}

TEST(EchConfigList, RejectsOuterLengthMismatch) {
    auto v = make_ech_config_list(1, 16);
    v.push_back(0xff);  // trailing junk breaks the exact-framing rule
    EXPECT_FALSE(ech::ech_config_list_looks_valid(v));
}

TEST(EchConfigList, RejectsInnerConfigOverrun) {
    // outer says 8 bytes follow; inner config claims a 0xffff body.
    std::vector<std::uint8_t> v = {0x00, 0x08, 0xfe, 0x0d, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00};
    EXPECT_FALSE(ech::ech_config_list_looks_valid(v));
}

TEST(EchBase64, RoundTripsValidConfig) {
    auto orig = make_ech_config_list(2, 24);
    auto decoded = ech::decode_ech_config_list_b64(b64(orig));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, orig);
}

TEST(EchBase64, RejectsGarbageBase64) {
    EXPECT_FALSE(ech::decode_ech_config_list_b64("!!!not base64!!!").has_value());
    EXPECT_FALSE(ech::decode_ech_config_list_b64("").has_value());
}

TEST(EchBase64, RejectsValidB64ButMalformedFraming) {
    // Valid base64, but the bytes aren't a well-framed ECHConfigList.
    EXPECT_FALSE(ech::decode_ech_config_list_b64(b64({0xde, 0xad, 0xbe, 0xef}))
                     .has_value());
}

TEST(EchTxtParam, ExtractsEchTokenFromFinbitRecord) {
    auto cfg = make_ech_config_list(1, 32);
    const std::string txt =
        "fb1 ed25519:6fa3 wss://relay.example.com:443 ech=" + b64(cfg);
    auto got = ech::parse_ech_param(txt);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, cfg);
}

TEST(EchTxtParam, NoneWhenAbsent) {
    EXPECT_FALSE(ech::parse_ech_param(
        "fb1 ed25519:6fa3 wss://relay.example.com:443").has_value());
}

TEST(EchTxtParam, SkipsMalformedEchTokenButFindsValidLater) {
    auto cfg = make_ech_config_list(1, 16);
    const std::string txt =
        "ech=not_valid_framing wss://x ech=" + b64(cfg);
    auto got = ech::parse_ech_param(txt);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, cfg);
}
