// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tier-4: verify the TLS ClientHello fingerprint shaping. We render the
// actual ClientHello bytes (via fb::net::debug_client_hello, which uses
// an in-memory BIO and the real apply_fingerprint path), parse the
// cipher-suite list and the supported_groups extension, and assert the
// kChrome profile reshapes them to a browser-like order — proving the
// JA3 cipher/group fields actually change on the wire.

#include "fb/net/tls_client.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace {

struct ClientHello {
    std::vector<std::uint16_t>                  ciphers;
    std::map<std::uint16_t, std::vector<std::uint8_t>> extensions;
    bool ok = false;
};

std::uint16_t be16(const std::vector<std::uint8_t>& b, std::size_t i) {
    return static_cast<std::uint16_t>((b[i] << 8) | b[i + 1]);
}

// Minimal TLS-record + ClientHello parser, enough to pull the cipher
// list and extensions. Returns ok=false on any bounds problem.
ClientHello parse_client_hello(const std::vector<std::uint8_t>& b) {
    ClientHello h;
    std::size_t i = 0;
    if (b.size() < 43) return h;
    if (b[0] != 0x16) return h;                 // handshake record
    // b[3..4] record length — skip, we index absolutely below.
    if (b[5] != 0x01) return h;                 // ClientHello
    i = 9;                                       // client_version
    i += 2;                                       // version
    i += 32;                                      // random
    if (i >= b.size()) return h;
    const std::size_t sid_len = b[i];
    i += 1 + sid_len;                             // session id
    if (i + 2 > b.size()) return h;
    const std::size_t cs_len = be16(b, i);
    i += 2;
    if (i + cs_len > b.size() || (cs_len % 2) != 0) return h;
    for (std::size_t j = 0; j < cs_len; j += 2) {
        h.ciphers.push_back(be16(b, i + j));
    }
    i += cs_len;
    if (i + 1 > b.size()) return h;
    const std::size_t comp_len = b[i];
    i += 1 + comp_len;                            // compression methods
    if (i + 2 > b.size()) return h;
    const std::size_t ext_total = be16(b, i);
    i += 2;
    const std::size_t ext_end = i + ext_total;
    if (ext_end > b.size()) return h;
    while (i + 4 <= ext_end) {
        const std::uint16_t type = be16(b, i);
        const std::size_t   len  = be16(b, i + 2);
        i += 4;
        if (i + len > ext_end) return h;
        h.extensions[type] = std::vector<std::uint8_t>(
            b.begin() + static_cast<std::ptrdiff_t>(i),
            b.begin() + static_cast<std::ptrdiff_t>(i + len));
        i += len;
    }
    h.ok = true;
    return h;
}

// supported_groups extension is type 0x000a: 2-byte list length then
// 2-byte group ids. Returns the first group id, if present.
std::optional<std::uint16_t> first_supported_group(const ClientHello& h) {
    auto it = h.extensions.find(0x000a);
    if (it == h.extensions.end()) return std::nullopt;
    const auto& d = it->second;
    if (d.size() < 4) return std::nullopt;
    return static_cast<std::uint16_t>((d[2] << 8) | d[3]);
}

// RFC 8701 GREASE values: both bytes equal and low nibble == 0xa.
bool is_grease(std::uint16_t v) {
    return (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a;
}
bool has_grease_extension(const ClientHello& h) {
    for (const auto& [type, _] : h.extensions) {
        if (is_grease(type)) return true;
    }
    return false;
}

constexpr std::uint16_t kTLS_AES_128_GCM_SHA256 = 0x1301;
constexpr std::uint16_t kTLS_AES_256_GCM_SHA384 = 0x1302;
constexpr std::uint16_t kGroupX25519            = 0x001d;

}  // namespace

TEST(TlsFingerprint, ChromeProfileReshapesClientHello) {
    auto bytes = fb::net::debug_client_hello(fb::net::TlsFingerprint::kChrome);
    if (bytes.empty()) GTEST_SKIP() << "OpenSSL not compiled in";

    auto h = parse_client_hello(bytes);
    ASSERT_TRUE(h.ok) << "failed to parse ClientHello";
    ASSERT_FALSE(h.ciphers.empty());

    // Chrome lists TLS_AES_128_GCM_SHA256 first among the TLS 1.3
    // suites; OpenSSL's default lists TLS_AES_256_GCM_SHA384 first.
    EXPECT_EQ(h.ciphers.front(), kTLS_AES_128_GCM_SHA256);

    // Chrome's first supported group is x25519.
    auto g = first_supported_group(h);
    ASSERT_TRUE(g.has_value()) << "no supported_groups extension";
    EXPECT_EQ(*g, kGroupX25519);

    // GREASE extensions are injected (browsers send them; OpenSSL's
    // default does not).
    EXPECT_TRUE(has_grease_extension(h)) << "no GREASE extension found";
}

TEST(TlsFingerprint, DefaultHasNoGreaseButChromeDoes) {
    auto chrome = fb::net::debug_client_hello(fb::net::TlsFingerprint::kChrome);
    auto deflt  = fb::net::debug_client_hello(fb::net::TlsFingerprint::kDefault);
    if (chrome.empty() || deflt.empty()) GTEST_SKIP() << "OpenSSL not compiled in";
    auto hc = parse_client_hello(chrome);
    auto hd = parse_client_hello(deflt);
    ASSERT_TRUE(hc.ok && hd.ok);
    EXPECT_TRUE(has_grease_extension(hc));
    EXPECT_FALSE(has_grease_extension(hd));
}

TEST(TlsFingerprint, ChromeDiffersFromDefault) {
    auto chrome  = fb::net::debug_client_hello(fb::net::TlsFingerprint::kChrome);
    auto deflt   = fb::net::debug_client_hello(fb::net::TlsFingerprint::kDefault);
    if (chrome.empty() || deflt.empty()) GTEST_SKIP() << "OpenSSL not compiled in";

    auto hc = parse_client_hello(chrome);
    auto hd = parse_client_hello(deflt);
    ASSERT_TRUE(hc.ok && hd.ok);

    // The shaping must actually change the cipher order: default leads
    // with AES-256, Chrome with AES-128.
    EXPECT_EQ(hc.ciphers.front(), kTLS_AES_128_GCM_SHA256);
    EXPECT_EQ(hd.ciphers.front(), kTLS_AES_256_GCM_SHA384);
    EXPECT_NE(hc.ciphers, hd.ciphers);
}

TEST(TlsFingerprint, FirefoxProfileParses) {
    auto bytes = fb::net::debug_client_hello(fb::net::TlsFingerprint::kFirefox);
    if (bytes.empty()) GTEST_SKIP() << "OpenSSL not compiled in";
    auto h = parse_client_hello(bytes);
    ASSERT_TRUE(h.ok);
    // Firefox also leads its TLS 1.3 suites with AES-128-GCM.
    EXPECT_EQ(h.ciphers.front(), kTLS_AES_128_GCM_SHA256);
    // x25519 is still the first negotiated group.
    auto g = first_supported_group(h);
    ASSERT_TRUE(g.has_value());
    EXPECT_EQ(*g, kGroupX25519);
}
