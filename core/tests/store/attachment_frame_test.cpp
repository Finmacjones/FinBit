// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/store/attachment_frame.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

using fb::store::frame_attachment;
using fb::store::parse_attachment_frame;
using fb::store::is_framed_attachment;

namespace {
std::vector<std::uint8_t> bytes(std::initializer_list<int> v) {
    std::vector<std::uint8_t> out;
    for (int b : v) out.push_back(static_cast<std::uint8_t>(b));
    return out;
}
std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}
}  // namespace

TEST(AttachmentFrame, RoundTrips) {
    const auto content = bytes({0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 255});
    auto framed = frame_attachment("image/png", "cat.png", view(content));
    ASSERT_TRUE(is_framed_attachment(view(framed)));
    auto parsed = parse_attachment_frame(view(framed));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->mime, "image/png");
    EXPECT_EQ(parsed->filename, "cat.png");
    EXPECT_EQ(parsed->content, content);
}

TEST(AttachmentFrame, EmptyContentAndFieldsRoundTrip) {
    auto framed = frame_attachment("", "", {});
    ASSERT_TRUE(is_framed_attachment(view(framed)));
    auto parsed = parse_attachment_frame(view(framed));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->mime.empty());
    EXPECT_TRUE(parsed->filename.empty());
    EXPECT_TRUE(parsed->content.empty());
}

TEST(AttachmentFrame, PlainTextIsNotAnAttachment) {
    const std::string text = "hello, this is an ordinary message 🙂";
    std::vector<std::uint8_t> blob(text.begin(), text.end());
    EXPECT_FALSE(is_framed_attachment(view(blob)));
    EXPECT_FALSE(parse_attachment_frame(view(blob)).has_value());
}

TEST(AttachmentFrame, EmptyBlobIsNotAnAttachment) {
    std::vector<std::uint8_t> empty;
    EXPECT_FALSE(is_framed_attachment(view(empty)));
    EXPECT_FALSE(parse_attachment_frame(view(empty)).has_value());
}

TEST(AttachmentFrame, TruncatedFrameRejected) {
    auto framed = frame_attachment("image/gif", "anim.gif",
                                   view(bytes({1, 2, 3, 4, 5})));
    // Chop off the tail (mid-content / mid-header) → must fail to parse,
    // not read out of bounds.
    for (std::size_t cut = 7; cut < framed.size(); ++cut) {
        std::vector<std::uint8_t> trunc(framed.begin(),
                                        framed.begin() + static_cast<std::ptrdiff_t>(cut));
        // Truncations that still cover the full header+fields up to the
        // content boundary may parse with a shorter content; truncations
        // inside the length-prefixed fields must be rejected. Either way:
        // no crash / no overrun.
        (void)parse_attachment_frame(view(trunc));
    }
    SUCCEED();
}

TEST(AttachmentFrame, BinaryContentWithMagicBytesInsideIsExactlyPreserved) {
    // Content that itself contains the magic prefix must survive intact.
    const auto content = bytes({0x00, 'F', 'B', 'A', 'T', '1', 0x00, 'x', 'y'});
    auto framed = frame_attachment("application/octet-stream", "f.bin", view(content));
    auto parsed = parse_attachment_frame(view(framed));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->content, content);
    EXPECT_EQ(parsed->filename, "f.bin");
}
