// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/frame_codec.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
std::span<const std::uint8_t> span_of(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}

}  // namespace

TEST(FrameCodec, EncodeDecodeRoundTrip) {
    const auto payload = bytes("hello world");
    const auto framed = fb::net::encode_frame(span_of(payload));
    EXPECT_EQ(framed.size(), 4u + payload.size());

    fb::net::FrameDecoder dec;
    dec.feed(span_of(framed));
    std::vector<std::uint8_t> out;
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kFrameReady);
    EXPECT_EQ(out, payload);
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kNeedMore);
}

TEST(FrameCodec, BackToBackFrames) {
    const auto a = bytes("alpha");
    const auto b = bytes("beta");
    auto fa = fb::net::encode_frame(span_of(a));
    auto fb_ = fb::net::encode_frame(span_of(b));
    fa.insert(fa.end(), fb_.begin(), fb_.end());

    fb::net::FrameDecoder dec;
    dec.feed(span_of(fa));
    std::vector<std::uint8_t> out;
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kFrameReady);
    EXPECT_EQ(out, a);
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kFrameReady);
    EXPECT_EQ(out, b);
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kNeedMore);
}

TEST(FrameCodec, ChunkedDelivery) {
    const auto payload = bytes("the quick brown fox jumps over the lazy dog");
    const auto framed = fb::net::encode_frame(span_of(payload));

    fb::net::FrameDecoder dec;
    std::vector<std::uint8_t> out;
    // Feed one byte at a time.
    for (auto b : framed) {
        std::array<std::uint8_t, 1> one{b};
        dec.feed(std::span<const std::uint8_t>(one.data(), one.size()));
    }
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kFrameReady);
    EXPECT_EQ(out, payload);
}

TEST(FrameCodec, RejectsOversizeFrame) {
    std::array<std::uint8_t, 4> bad_len = {0xff, 0xff, 0xff, 0xff};  // 4 GiB
    fb::net::FrameDecoder dec;
    dec.feed(std::span<const std::uint8_t>(bad_len.data(), bad_len.size()));
    std::vector<std::uint8_t> out;
    EXPECT_EQ(dec.try_pop(out), fb::net::FrameDecoder::Status::kError);
    EXPECT_TRUE(dec.has_error());
}
