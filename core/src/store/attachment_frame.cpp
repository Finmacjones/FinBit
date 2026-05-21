// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/store/attachment_frame.hpp"

#include <cstddef>

namespace fb::store {

namespace {
// NUL-led so it can never be the start of a valid UTF-8 chat message.
constexpr std::uint8_t kMagic[] = {0x00, 'F', 'B', 'A', 'T', '1', 0x00};
constexpr std::size_t  kMagicLen = sizeof(kMagic);

void put_u16(std::vector<std::uint8_t>& out, std::size_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}
}  // namespace

bool is_framed_attachment(std::span<const std::uint8_t> blob) {
    if (blob.size() < kMagicLen) return false;
    for (std::size_t i = 0; i < kMagicLen; ++i) {
        if (blob[i] != kMagic[i]) return false;
    }
    return true;
}

std::vector<std::uint8_t> frame_attachment(std::string_view mime,
                                           std::string_view filename,
                                           std::span<const std::uint8_t> content) {
    // Defensive truncation: the length prefixes are 16-bit.
    if (mime.size() > 0xFFFF)     mime = mime.substr(0, 0xFFFF);
    if (filename.size() > 0xFFFF) filename = filename.substr(0, 0xFFFF);

    std::vector<std::uint8_t> out;
    out.reserve(kMagicLen + 4 + mime.size() + filename.size() + content.size());
    out.insert(out.end(), kMagic, kMagic + kMagicLen);
    put_u16(out, mime.size());
    out.insert(out.end(), mime.begin(), mime.end());
    put_u16(out, filename.size());
    out.insert(out.end(), filename.begin(), filename.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

std::optional<AttachmentFrame> parse_attachment_frame(
    std::span<const std::uint8_t> blob) {
    if (!is_framed_attachment(blob)) return std::nullopt;
    std::size_t off = kMagicLen;
    auto need = [&](std::size_t n) { return off + n <= blob.size(); };
    auto get_u16 = [&]() -> std::size_t {
        const std::size_t v =
            (static_cast<std::size_t>(blob[off]) << 8) | blob[off + 1];
        off += 2;
        return v;
    };

    if (!need(2)) return std::nullopt;
    const std::size_t mime_len = get_u16();
    if (!need(mime_len)) return std::nullopt;
    AttachmentFrame f;
    f.mime.assign(reinterpret_cast<const char*>(blob.data() + off), mime_len);
    off += mime_len;

    if (!need(2)) return std::nullopt;
    const std::size_t fname_len = get_u16();
    if (!need(fname_len)) return std::nullopt;
    f.filename.assign(reinterpret_cast<const char*>(blob.data() + off), fname_len);
    off += fname_len;

    f.content.assign(blob.begin() + static_cast<std::ptrdiff_t>(off), blob.end());
    return f;
}

}  // namespace fb::store
