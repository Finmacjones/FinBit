// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the CLIENT-side WebSocket layer added for Tier-2
// censorship-resistance (the native client speaking real WSS):
//   - build_client_upgrade_request / ClientHandshakeParser
//   - build_client_binary_frame (masked, RFC 6455 §5.3)
//   - FrameParser{expect_masked} in both directions
//
// The server-side primitives (HandshakeParser, compute_accept,
// build_101_response, build_server_binary_frame) are exercised here too
// as the counterpart, so each test is a real client↔server loop.

#include "fb/net/websocket.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ws = fb::net::ws;

namespace {

std::vector<std::uint8_t> bytes(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

}  // namespace

// ----------------------------------------------------------------------------
// Masked client frames round-trip through the server's FrameParser
// ----------------------------------------------------------------------------

TEST(WsClientFrame, RoundTripsThroughServerParser) {
    const auto payload = bytes("hello finbit");
    const auto frame = ws::build_client_binary_frame(view(payload));

    ws::FrameParser server;  // default: expect_masked = true
    server.feed(view(frame));
    std::vector<std::uint8_t> out;
    ASSERT_EQ(server.try_pop(out), ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(out, payload);
}

TEST(WsClientFrame, RoundTrips16BitLengthPayload) {
    std::vector<std::uint8_t> payload(4000);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i & 0xff);
    }
    const auto frame = ws::build_client_binary_frame(view(payload));
    ws::FrameParser server;
    server.feed(view(frame));
    std::vector<std::uint8_t> out;
    ASSERT_EQ(server.try_pop(out), ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(out, payload);
}

TEST(WsClientFrame, RoundTrips64BitLengthPayload) {
    std::vector<std::uint8_t> payload(70000);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>((i * 7) & 0xff);
    }
    const auto frame = ws::build_client_binary_frame(view(payload));
    ws::FrameParser server;
    server.feed(view(frame));
    std::vector<std::uint8_t> out;
    ASSERT_EQ(server.try_pop(out), ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(out, payload);
}

TEST(WsClientFrame, MaskKeyIsRandomButDecodesSame) {
    const auto payload = bytes("same payload twice");
    const auto a = ws::build_client_binary_frame(view(payload));
    const auto b = ws::build_client_binary_frame(view(payload));
    // Overwhelmingly likely the two frames differ (random 32-bit mask).
    EXPECT_NE(a, b);
    // ...but both decode to the original payload.
    for (const auto& f : {a, b}) {
        ws::FrameParser server;
        server.feed(view(f));
        std::vector<std::uint8_t> out;
        ASSERT_EQ(server.try_pop(out), ws::FrameParser::PopStatus::kFrameReady);
        EXPECT_EQ(out, payload);
    }
}

// ----------------------------------------------------------------------------
// FrameParser direction enforcement
// ----------------------------------------------------------------------------

TEST(WsFrameParserDirection, ClientParserAcceptsUnmaskedServerFrame) {
    const auto payload = bytes("server says hi");
    const auto frame = ws::build_server_binary_frame(view(payload));  // unmasked
    ws::FrameParser client(/*expect_masked=*/false);
    client.feed(view(frame));
    std::vector<std::uint8_t> out;
    ASSERT_EQ(client.try_pop(out), ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(out, payload);
}

TEST(WsFrameParserDirection, ServerParserRejectsUnmaskedFrame) {
    const auto payload = bytes("unmasked is illegal from a client");
    const auto frame = ws::build_server_binary_frame(view(payload));  // unmasked
    ws::FrameParser server;  // expect_masked = true
    server.feed(view(frame));
    std::vector<std::uint8_t> out;
    EXPECT_EQ(server.try_pop(out), ws::FrameParser::PopStatus::kError);
    EXPECT_FALSE(server.error().empty());
}

// ----------------------------------------------------------------------------
// Full in-memory handshake loop: client → server → client
// ----------------------------------------------------------------------------

TEST(WsHandshake, FullLoopAccepts) {
    auto up = ws::build_client_upgrade_request("relay.example.com", 443, "/");
    ASSERT_FALSE(up.sec_key.empty());

    // Server parses the client's upgrade request.
    ws::HandshakeParser server;
    ASSERT_EQ(server.feed(view(up.request)),
              ws::HandshakeParser::Status::kAccepted);
    EXPECT_EQ(server.client_key(), up.sec_key);

    // Server builds its 101 response.
    const auto accept = ws::compute_accept(server.client_key());
    const auto resp = ws::build_101_response(accept);

    // Client validates the response against the key it sent.
    ws::ClientHandshakeParser client(up.sec_key);
    EXPECT_EQ(client.feed(view(resp)),
              ws::ClientHandshakeParser::Status::kAccepted);
}

TEST(WsHandshake, ClientRejectsBadAccept) {
    auto up = ws::build_client_upgrade_request("h", 443, "/");
    const auto resp = ws::build_101_response("not-the-right-accept-value");
    ws::ClientHandshakeParser client(up.sec_key);
    EXPECT_EQ(client.feed(view(resp)),
              ws::ClientHandshakeParser::Status::kRejected);
    EXPECT_FALSE(client.reason().empty());
}

TEST(WsHandshake, ClientRejectsNon101Status) {
    auto up = ws::build_client_upgrade_request("h", 443, "/");
    const auto accept = ws::compute_accept(up.sec_key);
    std::string s =
        "HTTP/1.1 200 OK\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
    ws::ClientHandshakeParser client(up.sec_key);
    EXPECT_EQ(client.feed(view(bytes(s))),
              ws::ClientHandshakeParser::Status::kRejected);
}

TEST(WsHandshake, ClientRejectsMissingUpgradeHeader) {
    auto up = ws::build_client_upgrade_request("h", 443, "/");
    const auto accept = ws::compute_accept(up.sec_key);
    std::string s =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
    ws::ClientHandshakeParser client(up.sec_key);
    EXPECT_EQ(client.feed(view(bytes(s))),
              ws::ClientHandshakeParser::Status::kRejected);
}

TEST(WsHandshake, ClientNeedsMoreOnPartialHeaders) {
    auto up = ws::build_client_upgrade_request("h", 443, "/");
    ws::ClientHandshakeParser client(up.sec_key);
    EXPECT_EQ(client.feed(view(bytes("HTTP/1.1 101 Switching Pro"))),
              ws::ClientHandshakeParser::Status::kNeedMore);
}

TEST(WsHandshake, ClientExposesTrailingBytesAfterHeaders) {
    auto up = ws::build_client_upgrade_request("h", 443, "/");
    const auto accept = ws::compute_accept(up.sec_key);
    // A server WS data frame piggy-backed right after the 101 headers.
    const auto trailing_frame = ws::build_server_binary_frame(view(bytes("early")));
    std::string headers =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
    std::vector<std::uint8_t> resp(headers.begin(), headers.end());
    resp.insert(resp.end(), trailing_frame.begin(), trailing_frame.end());

    ws::ClientHandshakeParser client(up.sec_key);
    ASSERT_EQ(client.feed(view(resp)),
              ws::ClientHandshakeParser::Status::kAccepted);

    // The trailing bytes feed straight into a client FrameParser.
    ws::FrameParser fp(/*expect_masked=*/false);
    fp.feed(client.trailing());
    std::vector<std::uint8_t> out;
    ASSERT_EQ(fp.try_pop(out), ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(out, bytes("early"));
}

// ----------------------------------------------------------------------------
// Upgrade-request shape (browser-like)
// ----------------------------------------------------------------------------

TEST(WsUpgradeRequest, OmitsDefaultPortInHostHeader) {
    auto up = ws::build_client_upgrade_request("example.com", 443, "/");
    const std::string req(up.request.begin(), up.request.end());
    EXPECT_NE(req.find("GET / HTTP/1.1\r\n"), std::string::npos);
    EXPECT_NE(req.find("Host: example.com\r\n"), std::string::npos);
    EXPECT_EQ(req.find("example.com:443"), std::string::npos);
    EXPECT_NE(req.find("Upgrade: websocket\r\n"), std::string::npos);
    EXPECT_NE(req.find("Connection: Upgrade\r\n"), std::string::npos);
    EXPECT_NE(req.find("Sec-WebSocket-Version: 13\r\n"), std::string::npos);
    EXPECT_NE(req.find("Sec-WebSocket-Key: "), std::string::npos);
}

TEST(WsUpgradeRequest, IncludesNonDefaultPortInHostHeader) {
    auto up = ws::build_client_upgrade_request("example.com", 8443, "/chat");
    const std::string req(up.request.begin(), up.request.end());
    EXPECT_NE(req.find("GET /chat HTTP/1.1\r\n"), std::string::npos);
    EXPECT_NE(req.find("Host: example.com:8443\r\n"), std::string::npos);
}

// Tier-2 L7 polish: the default request looks like a current Chrome.
TEST(WsUpgradeRequest, EmitsBrowserRealisticHeaders) {
    auto up = ws::build_client_upgrade_request("example.com", 443, "/");
    const std::string req(up.request.begin(), up.request.end());
    EXPECT_NE(req.find("User-Agent: Mozilla/5.0 "), std::string::npos);
    EXPECT_NE(req.find("Chrome/"), std::string::npos);
    EXPECT_NE(req.find("Pragma: no-cache\r\n"), std::string::npos);
    EXPECT_NE(req.find("Cache-Control: no-cache\r\n"), std::string::npos);
    EXPECT_NE(req.find("Accept-Encoding: gzip, deflate, br\r\n"), std::string::npos);
    EXPECT_NE(req.find("Accept-Language: "), std::string::npos);
    EXPECT_NE(req.find("Sec-WebSocket-Extensions: permessage-deflate"),
              std::string::npos);
    EXPECT_NE(req.find("Origin: https://example.com\r\n"), std::string::npos);
    // No FinBit-branded leak in the default profile.
    EXPECT_EQ(req.find("FinBit"), std::string::npos);
}

// The polished request must still be accepted by the server-side
// HandshakeParser (header order / extra headers don't break parsing).
TEST(WsUpgradeRequest, PolishedRequestStillAcceptedByServer) {
    auto up = ws::build_client_upgrade_request("relay.example.com", 443, "/");
    ws::HandshakeParser server;
    ASSERT_EQ(server.feed(view(up.request)),
              ws::HandshakeParser::Status::kAccepted);
    EXPECT_EQ(server.client_key(), up.sec_key);
}

TEST(WsUpgradeRequest, UserAgentAndOriginOverridable) {
    ws::WsUpgradeOptions o;
    o.user_agent = "curl/8.4.0";
    o.origin     = "https://front.example";
    o.browser_headers = false;
    auto up = ws::build_client_upgrade_request("real.example", 443, "/", o);
    const std::string req(up.request.begin(), up.request.end());
    EXPECT_NE(req.find("User-Agent: curl/8.4.0\r\n"), std::string::npos);
    EXPECT_NE(req.find("Origin: https://front.example\r\n"), std::string::npos);
    // browser_headers=false suppresses the extra set.
    EXPECT_EQ(req.find("Pragma:"), std::string::npos);
    EXPECT_EQ(req.find("Sec-WebSocket-Extensions:"), std::string::npos);
}

// Tier-3: the Host header is independent of the TLS SNI (front). The
// request builder only knows the Host (the real backend); the SNI is
// set separately on TlsClientOptions. Here we prove the Host carries
// the REAL backend even when it differs from a front domain.
TEST(WsUpgradeRequest, HostHeaderIsIndependentOfFrontSni) {
    // Caller fronts via SNI=front.example (set on the TLS layer) but
    // routes to real.backend.example via the Host header.
    auto up = ws::build_client_upgrade_request("real.backend.example", 443, "/");
    const std::string req(up.request.begin(), up.request.end());
    EXPECT_NE(req.find("Host: real.backend.example\r\n"), std::string::npos);
    // The front domain must NOT appear in the cleartext HTTP — only the
    // (encrypted) SNI carries it.
    EXPECT_EQ(req.find("front.example"), std::string::npos);
}
