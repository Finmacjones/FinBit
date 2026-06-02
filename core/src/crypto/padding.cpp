// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/padding.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>

namespace fb::crypto {

namespace {

// Default ladder. Powers of 4 from 256 → 65536 — chat traffic clusters
// strongly in the lower two buckets; the upper three cover quoted replies
// / inline attachments / media signaling.
constexpr std::array<std::size_t, 5> kDefaultBuckets{256, 1024, 4096, 16384, 65536};

}  // namespace

std::span<const std::size_t> default_padding_buckets() noexcept {
    return std::span<const std::size_t>(kDefaultBuckets.data(), kDefaultBuckets.size());
}

std::vector<std::uint8_t> pad_to_bucket(std::span<const std::uint8_t> plaintext,
                                         std::span<const std::size_t>  buckets) {
    if (buckets.empty()) {
        throw PaddingError("pad_to_bucket: empty bucket ladder");
    }
    // Need at least one byte for the 0x80 marker.
    const std::size_t needed = plaintext.size() + 1;

    std::size_t target = 0;
    for (std::size_t b : buckets) {
        if (b >= needed) { target = b; break; }
    }
    if (target == 0) {
        throw PaddingError(
            "pad_to_bucket: plaintext exceeds largest bucket "
            "(caller must chunk or supply a larger ladder)");
    }

    std::vector<std::uint8_t> out(target, 0);
    std::copy(plaintext.begin(), plaintext.end(), out.begin());
    out[plaintext.size()] = 0x80;
    // The 0x00 tail is already there (vector zero-init).
    return out;
}

std::vector<std::uint8_t> pad_to_bucket(std::span<const std::uint8_t> plaintext) {
    return pad_to_bucket(plaintext, default_padding_buckets());
}

std::vector<std::uint8_t> strip_padding(std::span<const std::uint8_t> padded) {
    if (padded.empty()) {
        throw PaddingError("strip_padding: empty input");
    }
    // Walk from the end past the 0x00 tail to find the 0x80 marker.
    std::size_t i = padded.size();
    while (i > 0 && padded[i - 1] == 0x00) {
        --i;
    }
    if (i == 0) {
        // All zeros — invalid (the marker is mandatory).
        throw PaddingError("strip_padding: no 0x80 marker (all-zero input)");
    }
    if (padded[i - 1] != 0x80) {
        throw PaddingError(
            "strip_padding: expected 0x80 marker before zero tail");
    }
    // Real plaintext is [0, i-1) — exclude the marker itself.
    const std::size_t plaintext_len = i - 1;
    std::vector<std::uint8_t> out;
    out.assign(padded.data(), padded.data() + plaintext_len);
    return out;
}

}  // namespace fb::crypto
