// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Message-size padding (bucket scheme).
//
// Pads plaintext to the next bucket size up before AEAD encryption, so the
// resulting ciphertext lengths cluster on a small finite set instead of
// leaking the actual message length to a network observer (relay, ISP,
// passive global adversary, Tor exit, etc.). Even when the *content* is E2E
// encrypted, raw lengths leak a surprising amount: a 38-byte ciphertext is
// almost always "ok" or "yes"; a 14 KB ciphertext is almost always a quoted
// reply.
//
// Scheme: ISO/IEC 7816-4 / RFC 7253 style — append `0x80` then 0x00 bytes
// up to the next bucket boundary. Strip by scanning from the end for the
// first non-zero byte; that byte MUST be 0x80 (else: malformed).
//
// Default buckets: {256, 1024, 4096, 16384, 65536} bytes. Tuned for
// chat traffic — most messages fit in 256 or 1024 (text + small reply),
// 4096 absorbs longer messages, 16k/64k cover small attachments / media
// signaling. Sender picks the smallest bucket >= len(plaintext)+1 (the +1
// is the mandatory 0x80 marker).
//
// Tradeoff: bandwidth amplification. A 12-byte "ok" becomes 256 bytes on
// the wire (21x). Acceptable for a chat application; the user choosing to
// bucket their messages is consciously trading bandwidth for metadata
// hiding. The helpers are pure / opt-in — call sites adopt them, the
// existing wire stays compatible until every endpoint pads.
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace fb::crypto {

// Default bucket ladder. Returns a span over the global constexpr table.
// Buckets are STRICTLY INCREASING; the smallest is large enough that even
// a 1-byte plaintext + the 0x80 marker fits in the first bucket.
[[nodiscard]] std::span<const std::size_t> default_padding_buckets() noexcept;

class PaddingError : public std::runtime_error {
 public:
    using std::runtime_error::runtime_error;
};

// Pad `plaintext` to the next bucket >= plaintext.size()+1. Returns the
// padded buffer. Throws PaddingError if plaintext is larger than the
// largest bucket (caller should chunk, or pick a larger ladder).
//
// Use `buckets = default_padding_buckets()` for the standard ladder.
// Pass a custom ladder for special call sites (e.g. media-signaling that
// has its own size distribution).
[[nodiscard]] std::vector<std::uint8_t> pad_to_bucket(
    std::span<const std::uint8_t> plaintext,
    std::span<const std::size_t>  buckets);

// Strip padding produced by pad_to_bucket. Returns the original plaintext.
// Throws PaddingError if `padded` doesn't end in [0x80, 0x00*]; this is a
// detection signal that the message wasn't padded or was tampered with.
[[nodiscard]] std::vector<std::uint8_t> strip_padding(
    std::span<const std::uint8_t> padded);

// Convenience overload using the default bucket ladder.
[[nodiscard]] std::vector<std::uint8_t> pad_to_bucket(
    std::span<const std::uint8_t> plaintext);

}  // namespace fb::crypto
