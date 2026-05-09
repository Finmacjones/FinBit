// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// fb::p2p::bootstrap gtests.
//
// Coverage:
//   - parse_bootstrap_text: happy path, blank lines + comments, malformed
//     hex / wrong length / missing scheme all skipped + counted
//   - load_bootstrap_file: opens a file, reads + parses
//   - load_default_bootstrap honors FB_BOOTSTRAP_FILE
// =============================================================================

#include "fb/p2p/bootstrap.hpp"

#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::string write_temp(const std::string& contents) {
    char tmpl[] = "/tmp/fb_bootstrap_XXXXXX";
    int fd = mkstemp(tmpl);
    EXPECT_GE(fd, 0);
    if (fd < 0) return {};
    std::string path = tmpl;
    {
        std::ofstream o(path);
        o << contents;
    }
    ::close(fd);
    return path;
}

}  // namespace

TEST(BootstrapParse, HappyPath) {
    const std::string text =
        "# header comment\n"
        "\n"
        "6fa3000000000000000000000000000000000000000000000000000000000000  wss://b1.example:443\n"
        "b801000000000000000000000000000000000000000000000000000000000000  tcp://203.0.113.5:8765\n"
        "\n";
    auto r = fb::p2p::parse_bootstrap_text(text);
    EXPECT_EQ(r.malformed_lines, 0u);
    ASSERT_EQ(r.peers.size(), 2u);
    EXPECT_EQ(r.peers[0].addr, "wss://b1.example:443");
    EXPECT_EQ(r.peers[0].pubkey.size(), 32u);
    EXPECT_EQ(r.peers[0].pubkey[0], 0x6f);
    EXPECT_EQ(r.peers[1].addr, "tcp://203.0.113.5:8765");
}

TEST(BootstrapParse, MalformedLinesCounted) {
    const std::string text =
        // Bad hex (odd length)
        "6fa3 wss://b1.example:443\n"
        // Wrong byte count (16 bytes hex, not 32)
        "6fa3000000000000000000000000000000  wss://b2.example:443\n"
        // Missing scheme
        "6fa3000000000000000000000000000000000000000000000000000000000000  b3.example:443\n"
        // OK
        "b801000000000000000000000000000000000000000000000000000000000000  wss://b4.example:443\n"
        // Missing addr
        "b801000000000000000000000000000000000000000000000000000000000000\n";
    auto r = fb::p2p::parse_bootstrap_text(text);
    EXPECT_EQ(r.peers.size(), 1u);
    EXPECT_EQ(r.malformed_lines, 4u);
    EXPECT_EQ(r.peers[0].addr, "wss://b4.example:443");
}

TEST(BootstrapParse, BlankLinesAndCommentsIgnored) {
    const std::string text =
        "\n"
        "  \n"
        "# leading comment\n"
        "   # indented comment\n"
        "\r\n";   // Windows-style blank line
    auto r = fb::p2p::parse_bootstrap_text(text);
    EXPECT_EQ(r.peers.size(), 0u);
    EXPECT_EQ(r.malformed_lines, 0u);
}

TEST(BootstrapFile, LoadFromDisk) {
    const std::string path = write_temp(
        "ABCDef000000000000000000000000000000000000000000000000000000abcd  wss://x.example:1\n");
    auto r = fb::p2p::load_bootstrap_file(path);
    ASSERT_EQ(r.peers.size(), 1u);
    EXPECT_EQ(r.peers[0].pubkey.front(), 0xab);
    EXPECT_EQ(r.peers[0].pubkey.back(),  0xcd);
    ::unlink(path.c_str());
}

TEST(BootstrapFile, MissingPathThrows) {
    EXPECT_THROW(fb::p2p::load_bootstrap_file("/nonexistent/path/finbit"),
                 std::runtime_error);
}

TEST(BootstrapDefault, EnvOverrideWins) {
    const std::string path = write_temp(
        "deadbeef00000000000000000000000000000000000000000000000000000000  tcp://e.example:7\n");
    setenv("FB_BOOTSTRAP_FILE", path.c_str(), /*overwrite=*/1);
    auto r = fb::p2p::load_default_bootstrap();
    unsetenv("FB_BOOTSTRAP_FILE");
    ASSERT_EQ(r.peers.size(), 1u);
    EXPECT_EQ(r.peers[0].addr, "tcp://e.example:7");
    ::unlink(path.c_str());
}
