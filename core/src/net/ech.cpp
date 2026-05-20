// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/ech.hpp"

#include <sodium.h>

#include <cctype>
#include <cstddef>

namespace fb::net::ech {

namespace {

std::uint16_t be16(const std::vector<std::uint8_t>& b, std::size_t i) {
    return static_cast<std::uint16_t>((b[i] << 8) | b[i + 1]);
}

}  // namespace

bool ech_config_list_looks_valid(const std::vector<std::uint8_t>& bytes) {
    // Outer: 2-byte length prefix.
    if (bytes.size() < 2) return false;
    const std::size_t inner_len = be16(bytes, 0);
    if (inner_len == 0) return false;                 // need >= 1 config
    if (bytes.size() != inner_len + 2) return false;  // exact framing

    // Walk the ECHConfig sequence: version(2) + length(2) + length bytes.
    std::size_t off = 2;
    std::size_t configs = 0;
    while (off < bytes.size()) {
        if (off + 4 > bytes.size()) return false;     // need version+length
        const std::size_t clen = be16(bytes, off + 2);
        off += 4;
        if (off + clen > bytes.size()) return false;  // body overruns
        off += clen;
        ++configs;
    }
    return off == bytes.size() && configs >= 1;
}

std::optional<std::vector<std::uint8_t>>
decode_ech_config_list_b64(std::string_view b64) {
    if (b64.empty()) return std::nullopt;
    std::vector<std::uint8_t> out(b64.size());  // decoded <= input size
    std::size_t out_len = 0;
    // Tolerate surrounding whitespace; reject any other stray chars.
    if (sodium_base642bin(out.data(), out.size(), b64.data(), b64.size(),
                          " \t\r\n", &out_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        return std::nullopt;
    }
    out.resize(out_len);
    if (!ech_config_list_looks_valid(out)) return std::nullopt;
    return out;
}

std::optional<std::vector<std::uint8_t>>
parse_ech_param(std::string_view txt_body) {
    constexpr std::string_view kPrefix = "ech=";
    std::size_t i = 0;
    const std::size_t n = txt_body.size();
    while (i < n) {
        // Skip whitespace to the start of a token.
        while (i < n && std::isspace(static_cast<unsigned char>(txt_body[i]))) ++i;
        const std::size_t start = i;
        while (i < n && !std::isspace(static_cast<unsigned char>(txt_body[i]))) ++i;
        const std::string_view tok = txt_body.substr(start, i - start);
        if (tok.size() > kPrefix.size() &&
            tok.substr(0, kPrefix.size()) == kPrefix) {
            if (auto bytes = decode_ech_config_list_b64(
                    tok.substr(kPrefix.size()))) {
                return bytes;
            }
            // Malformed ech= token — keep scanning in case another is valid.
        }
    }
    return std::nullopt;
}

}  // namespace fb::net::ech
