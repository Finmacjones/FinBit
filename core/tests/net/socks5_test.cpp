// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/socks5.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

using namespace fb::net::socks5;

// ============================================================================
// Pure wire-format tests — always run, no sockets.
// ============================================================================

TEST(Socks5Wire, GreetingIsThreeBytesNoAuth) {
    auto g = encode_greeting();
    EXPECT_EQ(g, (std::vector<std::uint8_t>{0x05, 0x01, 0x00}));
}

TEST(Socks5Wire, ParseGreetingResponse) {
    std::uint8_t ok[] = {0x05, 0x00};
    std::uint8_t rej[] = {0x05, 0xFF};
    std::uint8_t badver[] = {0x04, 0x00};
    std::uint8_t tooshort[] = {0x05};
    EXPECT_EQ(parse_greeting_response(std::span<const std::uint8_t>(ok, 2)),
              std::optional<std::uint8_t>{0x00});
    EXPECT_EQ(parse_greeting_response(std::span<const std::uint8_t>(rej, 2)),
              std::optional<std::uint8_t>{0xFF});
    EXPECT_FALSE(parse_greeting_response(
        std::span<const std::uint8_t>(badver, 2)).has_value());
    EXPECT_FALSE(parse_greeting_response(
        std::span<const std::uint8_t>(tooshort, 1)).has_value());
}

TEST(Socks5Wire, GreetingWithUserpassOffersBothMethods) {
    auto g = encode_greeting_with_userpass();
    EXPECT_EQ(g, (std::vector<std::uint8_t>{0x05, 0x02, 0x00, 0x02}));
}

TEST(Socks5Wire, UserpassAuthEncoding) {
    auto a = encode_userpass_auth("finbit:relay.example.com", "x");
    ASSERT_GE(a.size(), 3u);
    EXPECT_EQ(a[0], 0x01);            // sub-negotiation VER
    EXPECT_EQ(a[1], 24);              // ulen = strlen("finbit:relay.example.com")
    EXPECT_EQ(std::string(a.begin() + 2, a.begin() + 2 + 24),
              "finbit:relay.example.com");
    EXPECT_EQ(a[2 + 24], 1);          // plen
    EXPECT_EQ(a[2 + 24 + 1], 'x');
}

TEST(Socks5Wire, UserpassAuthTruncatesAtBoundary) {
    // 256-byte username gets clamped to 255 (RFC 1929 ulen is a byte).
    auto a = encode_userpass_auth(std::string(256, 'A'), "");
    EXPECT_EQ(a[1], 255);
    EXPECT_EQ(a.size(), 3u + 255);    // [0x01][ulen][user][plen=0]
    EXPECT_EQ(a[2 + 255], 0);
}

TEST(Socks5Wire, ParseUserpassResponse) {
    std::uint8_t ok[] = {0x01, 0x00};
    std::uint8_t fail[] = {0x01, 0xFF};
    std::uint8_t badver[] = {0x05, 0x00};
    EXPECT_EQ(parse_userpass_response(std::span<const std::uint8_t>(ok, 2)),
              std::optional<std::uint8_t>{0x00});
    EXPECT_EQ(parse_userpass_response(std::span<const std::uint8_t>(fail, 2)),
              std::optional<std::uint8_t>{0xFF});
    EXPECT_FALSE(parse_userpass_response(
        std::span<const std::uint8_t>(badver, 2)).has_value());
}

TEST(Socks5Wire, ConnectRequestDomainAtyp) {
    auto r = encode_connect_request("relay.example.com", 443);
    ASSERT_EQ(r.size(), 7u + 17u);   // header(4) + len(1) + name(17) + port(2)
    EXPECT_EQ(r[0], 0x05);            // VER
    EXPECT_EQ(r[1], 0x01);            // CMD = CONNECT
    EXPECT_EQ(r[2], 0x00);            // RSV
    EXPECT_EQ(r[3], 0x03);            // ATYP = domain
    EXPECT_EQ(r[4], 17);              // domain length
    EXPECT_EQ(std::string(r.begin() + 5, r.begin() + 5 + 17), "relay.example.com");
    EXPECT_EQ(r[5 + 17],     0x01);   // 443 BE high byte
    EXPECT_EQ(r[5 + 17 + 1], 0xBB);   // 443 BE low byte
}

TEST(Socks5Wire, ConnectResponseTailLengths) {
    EXPECT_EQ(connect_response_tail_len(0x01, 0), std::optional<std::size_t>{6});
    EXPECT_EQ(connect_response_tail_len(0x04, 0), std::optional<std::size_t>{18});
    EXPECT_EQ(connect_response_tail_len(0x03, 5),
              std::optional<std::size_t>{5 + 1 + 2});
    EXPECT_FALSE(connect_response_tail_len(0x99, 0).has_value());
}

TEST(Socks5Wire, ParseConnectResponseOkAndErrors) {
    // IPv4 success: VER REP RSV ATYP=01 ADDR(4) PORT(2)
    std::vector<std::uint8_t> ok = {0x05, 0x00, 0x00, 0x01, 127,0,0,1, 0,0};
    EXPECT_EQ(parse_connect_response(
        std::span<const std::uint8_t>(ok.data(), ok.size())),
              std::optional<Rep>{Rep::kSucceeded});

    // Refused (REP=0x05). Address still required by RFC; supply a valid tail.
    std::vector<std::uint8_t> refused = {0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0};
    EXPECT_EQ(parse_connect_response(
        std::span<const std::uint8_t>(refused.data(), refused.size())),
              std::optional<Rep>{Rep::kConnectionRefused});

    // Truncated.
    std::vector<std::uint8_t> trunc = {0x05, 0x00, 0x00, 0x01, 1,2,3};
    EXPECT_FALSE(parse_connect_response(
        std::span<const std::uint8_t>(trunc.data(), trunc.size())).has_value());
}

// ============================================================================
// Live transport — tiny in-process SOCKS5 stub on loopback. Skipped on Windows
// (no winsock setup in the test); the wire format above covers correctness.
// ============================================================================
#if !defined(_WIN32)

namespace {

// Bind a TCP socket on 127.0.0.1:0, return (fd, port). Caller closes the fd.
std::pair<int, std::uint16_t> bind_loopback() {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    ::listen(s, 4);
    socklen_t sl = sizeof(a);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &sl);
    return {s, ntohs(a.sin_port)};
}

// SOCKS5 stub that accepts ONE connection, replies success to NO_AUTH + CONNECT,
// records the requested target, then echoes any subsequent bytes back.
struct StubResult {
    std::string   target_host;
    std::uint16_t target_port = 0;
    std::string   echoed;
};

StubResult run_stub_once(int listen_fd, std::uint8_t connect_rep = 0x00) {
    StubResult res;
    int c = ::accept(listen_fd, nullptr, nullptr);
    if (c < 0) return res;

    // Greeting: read VER NMETHODS METHODS, reply NO_AUTH.
    std::uint8_t g[3];
    ::recv(c, g, 3, 0);
    std::uint8_t greet_rsp[2] = {0x05, 0x00};
    ::send(c, greet_rsp, 2, 0);

    // CONNECT: VER CMD RSV ATYP=03 LEN NAME PORT(BE)
    std::uint8_t hdr[5];
    ::recv(c, hdr, 5, 0);
    const std::uint8_t hlen = hdr[4];
    std::vector<std::uint8_t> name(hlen);
    ::recv(c, name.data(), hlen, 0);
    std::uint8_t portb[2];
    ::recv(c, portb, 2, 0);
    res.target_host.assign(name.begin(), name.end());
    res.target_port = static_cast<std::uint16_t>((portb[0] << 8) | portb[1]);

    // Reply (IPv4 0.0.0.0:0 as BND, REP=connect_rep).
    std::uint8_t rep[] = {0x05, connect_rep, 0x00, 0x01, 0,0,0,0, 0,0};
    ::send(c, rep, sizeof(rep), 0);

    if (connect_rep == 0x00) {
        // After success, echo whatever arrives (briefly) so the test can
        // exchange a byte through the "tunnel".
        std::uint8_t buf[16];
        const auto n = ::recv(c, buf, sizeof(buf), 0);
        if (n > 0) {
            res.echoed.assign(buf, buf + static_cast<std::size_t>(n));
            ::send(c, buf, static_cast<std::size_t>(n), 0);
        }
    }
    ::close(c);
    return res;
}

}  // namespace

TEST(Socks5Live, SuccessfulHandshakeAndTunnel) {
    auto [lfd, port] = bind_loopback();
    StubResult got;
    std::thread server([&] { got = run_stub_once(lfd); });

    fb::net::Socket s = socks5_connect("127.0.0.1", port,
                                        "relay.finbit.chat", 443);
    ASSERT_TRUE(s.valid());

    // Send a byte through the tunnel; the stub echoes it.
    const std::uint8_t hello[] = {'X'};
    while (s.write_some(std::span<const std::uint8_t>(hello, 1)) <= 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::uint8_t back[1] = {0};
    for (int i = 0; i < 200 && back[0] == 0; ++i) {
        s.read_some(std::span<std::uint8_t>(back, 1));
        if (back[0] == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    server.join();
    ::close(lfd);

    EXPECT_EQ(got.target_host, "relay.finbit.chat");
    EXPECT_EQ(got.target_port, 443);
    EXPECT_EQ(back[0], 'X');
}

TEST(Socks5Live, ConnectRefusedSurfacesRepCode) {
    auto [lfd, port] = bind_loopback();
    std::thread server([lfd] { run_stub_once(lfd, /*rep=*/0x05); });   // refused

    EXPECT_THROW({
        fb::net::Socket s = socks5_connect("127.0.0.1", port, "anywhere", 80);
        (void)s;
    }, SocksError);

    server.join();
    ::close(lfd);
}

#endif  // !_WIN32
