// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for fb::net::DoH bootstrap resolver.
//
// Covers ONLY the parsing layer — the network path (resolve_finbit_*)
// would need a fake TLS server or stubbed TlsClient to test without
// hitting the public internet. Parsing is what's at risk of churning,
// so it's where the unit tests live.

#include "fb/net/doh_resolver.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

using fb::net::parse_dns_json;
using fb::net::parse_finbit_txt;

// ----------------------------------------------------------------------------
// parse_finbit_txt — happy path + every grammar boundary
// ----------------------------------------------------------------------------

namespace {

// 32-byte hex pubkey for tests. The actual node-id derivation is
// content-addressed off this, but we don't check the id here — that's
// kademlia_test territory. We only assert pubkey + addr came through.
constexpr std::string_view kHexPub =
    "6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19";

}  // namespace

TEST(DohParseFinbitTxt, AcceptsCanonicalLine) {
    const std::string line =
        std::string("fb1 ed25519:") + std::string(kHexPub) +
        " wss://bootstrap-1.example.com:443";
    auto p = parse_finbit_txt(line);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->addr, "wss://bootstrap-1.example.com:443");
    EXPECT_EQ(p->pubkey.size(), 32u);
}

TEST(DohParseFinbitTxt, AcceptsCertPinnedAddr) {
    // The #<sha256fp> suffix is part of the addr field — opaque to
    // the parser, will be honored by PeerNet at dial time.
    const std::string line =
        std::string("fb1 ed25519:") + std::string(kHexPub) +
        " wss://bootstrap-1.example.com:443#"
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    auto p = parse_finbit_txt(line);
    ASSERT_TRUE(p.has_value());
    EXPECT_NE(p->addr.find("#a1b2c3d4"), std::string::npos);
}

TEST(DohParseFinbitTxt, RejectsMissingFb1Prefix) {
    // Wrong version marker.
    const std::string line =
        std::string("fb2 ed25519:") + std::string(kHexPub) +
        " wss://example.com:443";
    EXPECT_FALSE(parse_finbit_txt(line).has_value());
}

TEST(DohParseFinbitTxt, RejectsMissingEd25519Tag) {
    const std::string line =
        std::string("fb1 ") + std::string(kHexPub) +
        " wss://example.com:443";
    EXPECT_FALSE(parse_finbit_txt(line).has_value());
}

TEST(DohParseFinbitTxt, RejectsWrongPubkeyLength) {
    const std::string line =
        "fb1 ed25519:6fa31b3d wss://example.com:443";
    EXPECT_FALSE(parse_finbit_txt(line).has_value());
}

TEST(DohParseFinbitTxt, RejectsNonHexPubkey) {
    // 'z' is not a hex nibble.
    const std::string line =
        "fb1 ed25519:zfa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19"
        " wss://example.com:443";
    EXPECT_FALSE(parse_finbit_txt(line).has_value());
}

TEST(DohParseFinbitTxt, RejectsMissingAddr) {
    const std::string line =
        std::string("fb1 ed25519:") + std::string(kHexPub);
    EXPECT_FALSE(parse_finbit_txt(line).has_value());
}

TEST(DohParseFinbitTxt, RejectsEmpty) {
    EXPECT_FALSE(parse_finbit_txt("").has_value());
}

TEST(DohParseFinbitTxt, ToleratesLeadingTrailingWhitespace) {
    const std::string line =
        "   fb1 ed25519:" + std::string(kHexPub) +
        " wss://example.com:443\t\n";
    auto p = parse_finbit_txt(line);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->addr, "wss://example.com:443");
}

// ----------------------------------------------------------------------------
// parse_dns_json — Cloudflare / Google application/dns-json wire format
// ----------------------------------------------------------------------------

// Real Cloudflare-style response: top-level object, "Answer" array,
// each element has "name", "type", "TTL", "data" — and "data" is
// JSON-encoded with the surrounding double-quotes preserved per RFC
// 1035 character-string format.
TEST(DohParseDnsJson, ExtractsSingleTxtRecord) {
    const std::string body = R"({
      "Status": 0,
      "TC": false,
      "RD": true,
      "RA": true,
      "AD": false,
      "CD": false,
      "Question": [{"name":"_finbit.example.com","type":16}],
      "Answer": [
        {
          "name": "_finbit.example.com",
          "type": 16,
          "TTL": 300,
          "data": "\"fb1 ed25519:6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19 wss://relay-1.example.com:443\""
        }
      ]
    })";
    auto peers = parse_dns_json(body);
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].addr, "wss://relay-1.example.com:443");
}

TEST(DohParseDnsJson, ExtractsMultipleTxtRecords) {
    const std::string body = R"({
      "Status": 0,
      "Answer": [
        {
          "name":"_finbit.example.com","type":16,"TTL":300,
          "data":"\"fb1 ed25519:6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19 wss://relay-1.example.com:443\""
        },
        {
          "name":"_finbit.example.com","type":16,"TTL":300,
          "data":"\"fb1 ed25519:6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c1e wss://relay-2.example.com:443\""
        }
      ]
    })";
    auto peers = parse_dns_json(body);
    ASSERT_EQ(peers.size(), 2u);
    EXPECT_EQ(peers[0].addr, "wss://relay-1.example.com:443");
    EXPECT_EQ(peers[1].addr, "wss://relay-2.example.com:443");
}

TEST(DohParseDnsJson, SkipsNonTxtTypes) {
    // type 1 (A record) must be ignored even if data looks parseable.
    const std::string body = R"({
      "Answer": [
        {"name":"x","type":1,"TTL":300,"data":"203.0.113.5"},
        {"name":"_finbit.example.com","type":16,"TTL":300,
         "data":"\"fb1 ed25519:6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19 wss://relay-1.example.com:443\""}
      ]
    })";
    auto peers = parse_dns_json(body);
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].addr, "wss://relay-1.example.com:443");
}

TEST(DohParseDnsJson, SkipsNonFinbitTxtRecords) {
    // Domain owners often have unrelated TXT records (SPF, DMARC, etc.).
    // Our resolver shares the namespace cheerfully — those just don't
    // match the fb1 grammar and should be silently dropped.
    const std::string body = R"({
      "Answer": [
        {"name":"example.com","type":16,"TTL":300,
         "data":"\"v=spf1 -all\""},
        {"name":"_finbit.example.com","type":16,"TTL":300,
         "data":"\"fb1 ed25519:6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19 wss://relay-1.example.com:443\""}
      ]
    })";
    auto peers = parse_dns_json(body);
    ASSERT_EQ(peers.size(), 1u);
}

TEST(DohParseDnsJson, ReturnsEmptyOnNoAnswer) {
    const std::string body = R"({"Status": 3, "Answer": []})";
    auto peers = parse_dns_json(body);
    EXPECT_TRUE(peers.empty());
}

TEST(DohParseDnsJson, ReturnsEmptyOnGarbage) {
    EXPECT_TRUE(parse_dns_json("not json at all").empty());
    EXPECT_TRUE(parse_dns_json("").empty());
    EXPECT_TRUE(parse_dns_json("{}").empty());
}

TEST(DohParseDnsJson, HandlesEscapedQuotesInsideTxt) {
    // Some DoH servers escape the surrounding quotes; the inner record
    // body remains valid. Reads: data is a JSON string containing
    //   "fb1 ed25519:... wss://..."
    // with both leading/trailing quote characters present.
    const std::string body = R"({
      "Answer": [
        {"type":16,"data":"\"fb1 ed25519:6fa31b3d8c5a2710f4d0e8c9b1a3f5e72d6b8c0a4e1d3f5a7b9c1e3d5f7a9c19 wss://r.example.com:443\""}
      ]
    })";
    auto peers = parse_dns_json(body);
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].addr, "wss://r.example.com:443");
}
