// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Local-store framing for inline attachments (images / GIFs / small files).
//
// The message store (sqlite_store) keeps one opaque, AEAD-wrapped `plaintext`
// column per message. Text rows store the raw UTF-8 message; to persist an
// attachment WITHOUT a schema change we pack mime+filename+content into a
// single self-describing blob and store THAT in the same column. A NUL-led
// magic prefix — which valid UTF-8 chat text never starts with — lets the
// load path tell a framed attachment from plain text. The store still just
// wraps/returns opaque bytes; only the caller (chat_client) knows the framing.
//
// Layout:
//   magic(7) | u16 mime_len(BE) | mime | u16 fname_len(BE) | fname | content
// =============================================================================

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fb::store {

struct AttachmentFrame {
    std::string               mime;
    std::string               filename;
    std::vector<std::uint8_t> content;
};

// Pack an attachment into a framed blob suitable for the store's plaintext
// column. mime/filename are capped at 65535 bytes (u16 length prefix).
[[nodiscard]] std::vector<std::uint8_t> frame_attachment(
    std::string_view mime, std::string_view filename,
    std::span<const std::uint8_t> content);

// Parse a stored blob. Returns the attachment iff `blob` carries the magic
// and frames correctly; otherwise nullopt (⇒ the caller treats `blob` as
// plain text, preserving every pre-attachment row).
[[nodiscard]] std::optional<AttachmentFrame> parse_attachment_frame(
    std::span<const std::uint8_t> blob);

// True if `blob` begins with the attachment magic (cheap check before a
// full parse).
[[nodiscard]] bool is_framed_attachment(std::span<const std::uint8_t> blob);

}  // namespace fb::store
