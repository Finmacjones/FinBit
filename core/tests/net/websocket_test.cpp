// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/websocket.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> from_str(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

// Build a client-side WS frame manually so we can drive FrameParser tests.
std::vector<std::uint8_t> build_client_binary_frame(std::span<const std::uint8_t> payload,
                                                     bool fin = true) {
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>((fin ? 0x80 : 0x00) | 0x02));  // binary
    if (payload.size() < 126) {
        out.push_back(static_cast<std::uint8_t>(0x80 | payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        out.push_back(static_cast<std::uint8_t>(0x80 | 126));
        out.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(payload.size() & 0xff));
    } else {
        out.push_back(static_cast<std::uint8_t>(0x80 | 127));
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<std::uint8_t>((payload.size() >> (i * 8)) & 0xff));
        }
    }
    const std::uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
    out.insert(out.end(), mask, mask + 4);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        out.push_back(static_cast<std::uint8_t>(payload[i] ^ mask[i & 3]));
    }
    return out;
}

}  // namespace

// RFC 6455 §1.3 example: key "dGhlIHNhbXBsZSBub25jZQ==" → accept
// "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
TEST(WebSocketHandshake, RfcExampleAccept) {
    EXPECT_EQ(fb::net::ws::compute_accept("dGhlIHNhbXBsZSBub25jZQ=="),
              "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST(WebSocketHandshake, ParserAcceptsValidUpgrade) {
    fb::net::ws::HandshakeParser p;
    const auto req = from_str(
        "GET /chat HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n");
    EXPECT_EQ(p.feed(std::span<const std::uint8_t>(req.data(), req.size())),
              fb::net::ws::HandshakeParser::Status::kAccepted);
    EXPECT_EQ(p.client_key(), "dGhlIHNhbXBsZSBub25jZQ==");
}

TEST(WebSocketHandshake, ParserRejectsNonUpgrade) {
    fb::net::ws::HandshakeParser p;
    const auto req = from_str("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    EXPECT_EQ(p.feed(std::span<const std::uint8_t>(req.data(), req.size())),
              fb::net::ws::HandshakeParser::Status::kRejected);
}

TEST(WebSocketHandshake, ParserStreamsAcrossMultipleChunks) {
    fb::net::ws::HandshakeParser p;
    const std::string head =
        "GET / HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc==\r\n";
    const std::string tail = "\r\n";
    auto h = from_str(head);
    auto t = from_str(tail);
    EXPECT_EQ(p.feed(std::span<const std::uint8_t>(h.data(), h.size())),
              fb::net::ws::HandshakeParser::Status::kNeedMore);
    EXPECT_EQ(p.feed(std::span<const std::uint8_t>(t.data(), t.size())),
              fb::net::ws::HandshakeParser::Status::kAccepted);
    EXPECT_EQ(p.client_key(), "abc==");
}

TEST(WebSocketFraming, SmallPayloadRoundTrip) {
    const auto payload = from_str("hello");
    auto wire = build_client_binary_frame(
        std::span<const std::uint8_t>(payload.data(), payload.size()));
    fb::net::ws::FrameParser fp;
    fp.feed(std::span<const std::uint8_t>(wire.data(), wire.size()));
    std::vector<std::uint8_t> got;
    EXPECT_EQ(fp.try_pop(got), fb::net::ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(got, payload);
}

TEST(WebSocketFraming, ExtendedLength16) {
    std::vector<std::uint8_t> payload(300, 0x42);  // forces 16-bit ext length
    auto wire = build_client_binary_frame(
        std::span<const std::uint8_t>(payload.data(), payload.size()));
    fb::net::ws::FrameParser fp;
    fp.feed(std::span<const std::uint8_t>(wire.data(), wire.size()));
    std::vector<std::uint8_t> got;
    EXPECT_EQ(fp.try_pop(got), fb::net::ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(got, payload);
}

TEST(WebSocketFraming, MultiFragmentMessage) {
    auto a = from_str("part-1");
    auto b = from_str("part-2");
    auto frag1 = build_client_binary_frame(
        std::span<const std::uint8_t>(a.data(), a.size()), /*fin=*/false);
    // Continuation frame (opcode 0x0).
    std::vector<std::uint8_t> frag2;
    frag2.push_back(0x80);  // FIN + opcode 0 (continuation)
    frag2.push_back(static_cast<std::uint8_t>(0x80 | b.size()));
    const std::uint8_t mask[4] = {1, 2, 3, 4};
    frag2.insert(frag2.end(), mask, mask + 4);
    for (std::size_t i = 0; i < b.size(); ++i) {
        frag2.push_back(static_cast<std::uint8_t>(b[i] ^ mask[i & 3]));
    }

    fb::net::ws::FrameParser fp;
    fp.feed(std::span<const std::uint8_t>(frag1.data(), frag1.size()));
    std::vector<std::uint8_t> got;
    EXPECT_EQ(fp.try_pop(got), fb::net::ws::FrameParser::PopStatus::kNeedMore);
    fp.feed(std::span<const std::uint8_t>(frag2.data(), frag2.size()));
    EXPECT_EQ(fp.try_pop(got), fb::net::ws::FrameParser::PopStatus::kFrameReady);
    EXPECT_EQ(got, from_str("part-1part-2"));
}

TEST(WebSocketFraming, RejectsUnmaskedClientFrame) {
    std::vector<std::uint8_t> wire = {0x82, 0x05, 'h', 'e', 'l', 'l', 'o'};  // no mask bit
    fb::net::ws::FrameParser fp;
    fp.feed(std::span<const std::uint8_t>(wire.data(), wire.size()));
    std::vector<std::uint8_t> got;
    EXPECT_EQ(fp.try_pop(got), fb::net::ws::FrameParser::PopStatus::kError);
}

TEST(WebSocketFraming, ServerFrameBuilderRoundTripsViaParserBidirectionally) {
    // Build a server frame, then parse using a temporary client-style
    // un-mask path (we don't have a client-side parser, so this test
    // just sanity-checks the bytes are well-formed: opcode, length).
    auto pl = from_str("ping");
    auto frame = fb::net::ws::build_server_binary_frame(
        std::span<const std::uint8_t>(pl.data(), pl.size()));
    ASSERT_GE(frame.size(), 6u);
    EXPECT_EQ(frame[0], 0x82);  // FIN + binary
    EXPECT_EQ(frame[1], 0x04);  // length, no mask bit (server-to-client)
    EXPECT_EQ(std::string(frame.begin() + 2, frame.end()), "ping");
}
