// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Length-prefixed binary framing.
//
// Wire format: [u32 big-endian length][N bytes payload]
// Payload is a serialized fb.proto.Frame protobuf. Max payload is 8 MiB to
// bound buffer growth on a misbehaving peer.
//
// FrameDecoder is a stateful streaming parser: feed it bytes from a recv()
// in any chunking; it yields complete frames as they arrive. Use one instance
// per connection.
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace fb::net {

inline constexpr std::size_t kMaxFrameBytes = 8 * 1024 * 1024;

// Returns [length-prefix || payload] ready to send().
[[nodiscard]] std::vector<std::uint8_t> encode_frame(std::span<const std::uint8_t> payload);

class FrameDecoder {
public:
    enum class Status { kNeedMore, kFrameReady, kError };

    // Append raw bytes to the internal buffer.
    void feed(std::span<const std::uint8_t> bytes);

    // Pull the next ready frame, if any. On kFrameReady, `out` is populated
    // and the frame is consumed from the buffer. On kError the connection
    // should be closed (frame too large or stream desynced).
    [[nodiscard]] Status try_pop(std::vector<std::uint8_t>& out);

    [[nodiscard]] bool has_error() const noexcept { return error_; }
    [[nodiscard]] const std::string& last_error() const noexcept { return error_msg_; }

private:
    std::vector<std::uint8_t> buf_;
    bool error_ = false;
    std::string error_msg_;
};

}  // namespace fb::net
