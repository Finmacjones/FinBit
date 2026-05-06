// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Minimal RFC 6455 WebSocket — server-side termination only.
//
// We need just enough WebSocket to let a browser talk to fb_server: HTTP/1.1
// upgrade handshake, server frame builder, and a stateful client-side
// frame parser that handles fragmentation, masking, and the 16/64-bit
// extended payload-length forms.
//
// The decoder hands fully-assembled binary message payloads to the existing
// fb::net::FrameDecoder (which then deframes our length-prefixed Frame
// protobuf protocol). Server-to-client always sends single-frame, unmasked
// binary opcodes.
//
// Not implemented (deliberate, Phase 2 scope):
//   - permessage-deflate compression
//   - text frames (we always use binary)
//   - control-frame fragmentation (those are illegal per spec anyway)
//   - subprotocol negotiation (FinBit doesn't use one yet)
// =============================================================================

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace fb::net::ws {

// Returns the RFC 6455 Sec-WebSocket-Accept response value (base64 of
// SHA-1 of `client_key + GUID`). GUID is the well-known constant.
[[nodiscard]] std::string compute_accept(const std::string& client_key);

// HTTP upgrade-request parser. Streamed: feed bytes; once the full
// "\r\n\r\n" header block is observed and contains the right Upgrade:
// websocket + Sec-WebSocket-Key headers, returns the key (base64) so the
// caller can build the 101 response.
class HandshakeParser {
public:
    enum class Status { kNeedMore, kAccepted, kRejected };

    Status feed(std::span<const std::uint8_t> bytes);

    [[nodiscard]] const std::string& client_key() const noexcept { return client_key_; }
    [[nodiscard]] const std::string& reason() const noexcept { return reason_; }

    // Bytes left in the buffer after the "\r\n\r\n" header terminator —
    // the first WS frame may follow immediately. Caller drains these
    // before switching to FrameDecoder.
    [[nodiscard]] std::span<const std::uint8_t> trailing() const noexcept {
        return std::span<const std::uint8_t>(buf_.data() + headers_end_,
                                              buf_.size() - headers_end_);
    }

private:
    std::vector<std::uint8_t> buf_;
    std::size_t headers_end_ = 0;
    std::string client_key_;
    std::string reason_;
};

// Build the HTTP/1.1 101 Switching Protocols response.
[[nodiscard]] std::vector<std::uint8_t> build_101_response(const std::string& accept);

// Build a server-to-client binary frame (no mask, single fragment).
[[nodiscard]] std::vector<std::uint8_t> build_server_binary_frame(
    std::span<const std::uint8_t> payload);

// Build a server-to-client close frame with no body.
[[nodiscard]] std::vector<std::uint8_t> build_close_frame();

// Streaming WS frame parser. Feed raw post-handshake bytes; pop assembled
// binary messages.
class FrameParser {
public:
    enum class PopStatus { kNeedMore, kFrameReady, kClose, kError };

    void feed(std::span<const std::uint8_t> bytes);
    [[nodiscard]] PopStatus try_pop(std::vector<std::uint8_t>& out);
    [[nodiscard]] const std::string& error() const noexcept { return error_; }

private:
    std::vector<std::uint8_t> buf_;
    // For multi-fragment messages we accumulate here.
    std::vector<std::uint8_t> partial_;
    bool in_fragment_ = false;
    std::string error_;
};

}  // namespace fb::net::ws
