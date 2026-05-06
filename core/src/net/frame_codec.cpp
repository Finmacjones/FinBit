// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/frame_codec.hpp"

namespace fb::net {

std::vector<std::uint8_t> encode_frame(std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + payload.size());
    const auto len = static_cast<std::uint32_t>(payload.size());
    out.push_back(static_cast<std::uint8_t>((len >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((len >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(len & 0xff));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

void FrameDecoder::feed(std::span<const std::uint8_t> bytes) {
    if (error_) return;
    buf_.insert(buf_.end(), bytes.begin(), bytes.end());
}

FrameDecoder::Status FrameDecoder::try_pop(std::vector<std::uint8_t>& out) {
    if (error_) return Status::kError;
    if (buf_.size() < 4) return Status::kNeedMore;
    const std::uint32_t len = (static_cast<std::uint32_t>(buf_[0]) << 24) |
                              (static_cast<std::uint32_t>(buf_[1]) << 16) |
                              (static_cast<std::uint32_t>(buf_[2]) << 8) |
                              static_cast<std::uint32_t>(buf_[3]);
    if (len > kMaxFrameBytes) {
        error_ = true;
        error_msg_ = "frame exceeds kMaxFrameBytes";
        return Status::kError;
    }
    if (buf_.size() < 4 + len) return Status::kNeedMore;
    out.assign(buf_.begin() + 4, buf_.begin() + 4 + len);
    buf_.erase(buf_.begin(), buf_.begin() + 4 + len);
    return Status::kFrameReady;
}

}  // namespace fb::net
