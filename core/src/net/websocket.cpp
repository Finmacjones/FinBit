// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/websocket.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace fb::net::ws {
namespace {

constexpr std::string_view kMagicGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::size_t kMaxMessageBytes = 8 * 1024 * 1024;

std::string to_base64(std::span<const std::uint8_t> bin) {
    const std::size_t enc_len =
        sodium_base64_ENCODED_LEN(bin.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string out(enc_len, '\0');
    sodium_bin2base64(out.data(), out.size(), bin.data(), bin.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::string trim_ws(std::string s) {
    auto issp = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && issp(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && issp(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

bool icontains(const std::string& haystack, std::string_view needle) {
    auto it = std::search(haystack.begin(), haystack.end(),
                          needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

}  // namespace

std::string compute_accept(const std::string& client_key) {
    if (sodium_init() < 0) return {};
    std::string concat = client_key;
    concat.append(kMagicGuid);
    std::array<std::uint8_t, 20> sha1{};  // RFC 6455 specifies SHA-1
    // libsodium doesn't expose SHA-1; implement RFC 3174 inline.
    {
        // Minimal RFC 3174 SHA-1 — just for the WS handshake. Length-fits
        // is small (key is 24 chars + 36 chars magic = 60 chars), single
        // padded block path.
        std::uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
        std::vector<std::uint8_t> msg(concat.begin(), concat.end());
        const std::uint64_t bit_len = msg.size() * 8ULL;
        msg.push_back(0x80);
        while (msg.size() % 64 != 56) msg.push_back(0);
        for (int i = 7; i >= 0; --i) msg.push_back(static_cast<std::uint8_t>((bit_len >> (i * 8)) & 0xff));

        for (std::size_t off = 0; off < msg.size(); off += 64) {
            std::uint32_t w[80]{};
            for (int i = 0; i < 16; ++i) {
                w[i] = (static_cast<std::uint32_t>(msg[off + i * 4]) << 24) |
                       (static_cast<std::uint32_t>(msg[off + i * 4 + 1]) << 16) |
                       (static_cast<std::uint32_t>(msg[off + i * 4 + 2]) << 8) |
                       static_cast<std::uint32_t>(msg[off + i * 4 + 3]);
            }
            for (int i = 16; i < 80; ++i) {
                std::uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
                w[i] = (v << 1) | (v >> 31);
            }
            std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
            for (int i = 0; i < 80; ++i) {
                std::uint32_t f, k;
                if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999u; }
                else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
                std::uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
                e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = t;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        }
        for (int i = 0; i < 5; ++i) {
            sha1[i * 4 + 0] = static_cast<std::uint8_t>((h[i] >> 24) & 0xff);
            sha1[i * 4 + 1] = static_cast<std::uint8_t>((h[i] >> 16) & 0xff);
            sha1[i * 4 + 2] = static_cast<std::uint8_t>((h[i] >> 8) & 0xff);
            sha1[i * 4 + 3] = static_cast<std::uint8_t>(h[i] & 0xff);
        }
    }
    return to_base64(std::span<const std::uint8_t>(sha1.data(), sha1.size()));
}

HandshakeParser::Status HandshakeParser::feed(std::span<const std::uint8_t> bytes) {
    buf_.insert(buf_.end(), bytes.begin(), bytes.end());
    // Look for "\r\n\r\n".
    static const std::uint8_t terminator[] = {'\r', '\n', '\r', '\n'};
    auto it = std::search(buf_.begin(), buf_.end(),
                          std::begin(terminator), std::end(terminator));
    if (it == buf_.end()) {
        if (buf_.size() > 16384) {
            reason_ = "headers too large";
            return Status::kRejected;
        }
        return Status::kNeedMore;
    }
    headers_end_ = static_cast<std::size_t>((it - buf_.begin()) + 4);
    const std::string headers(buf_.begin(), buf_.begin() + headers_end_);

    if (!icontains(headers, "Upgrade: websocket") &&
        !icontains(headers, "upgrade: websocket")) {
        reason_ = "not a WebSocket upgrade";
        return Status::kRejected;
    }
    // Extract Sec-WebSocket-Key.
    const std::string needle = "sec-websocket-key:";
    const std::string lower_h = [&]() {
        std::string s = headers;
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }();
    const auto pos = lower_h.find(needle);
    if (pos == std::string::npos) {
        reason_ = "missing Sec-WebSocket-Key";
        return Status::kRejected;
    }
    const auto eol = headers.find("\r\n", pos);
    client_key_ = trim_ws(headers.substr(pos + needle.size(), eol - pos - needle.size()));
    if (client_key_.empty()) {
        reason_ = "empty Sec-WebSocket-Key";
        return Status::kRejected;
    }
    return Status::kAccepted;
}

std::vector<std::uint8_t> build_101_response(const std::string& accept) {
    std::string s =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::vector<std::uint8_t> build_server_binary_frame(std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> out;
    out.push_back(0x82);  // FIN + opcode binary
    if (payload.size() < 126) {
        out.push_back(static_cast<std::uint8_t>(payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        out.push_back(126);
        out.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(payload.size() & 0xff));
    } else {
        out.push_back(127);
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<std::uint8_t>((payload.size() >> (i * 8)) & 0xff));
        }
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> build_close_frame() {
    return {0x88, 0x00};
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

ClientUpgrade build_client_upgrade_request(const std::string& host,
                                           std::uint16_t port,
                                           const std::string& path) {
    ClientUpgrade up;

    // 16 random bytes → base64 = the Sec-WebSocket-Key (RFC 6455 §4.1).
    std::array<std::uint8_t, 16> key_raw{};
    if (sodium_init() >= 0) {
        randombytes_buf(key_raw.data(), key_raw.size());
    }
    up.sec_key = to_base64(std::span<const std::uint8_t>(key_raw.data(), key_raw.size()));

    // Host header omits the port when it's the wss:// default (443), so
    // the request matches what a browser emits for wss://host/path.
    std::string host_hdr = host;
    if (port != 443) host_hdr += ":" + std::to_string(port);

    std::string req;
    req += "GET " + (path.empty() ? std::string("/") : path) + " HTTP/1.1\r\n";
    req += "Host: " + host_hdr + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + up.sec_key + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    // A browser also sends Origin / User-Agent; include a believable
    // Origin so an L7 DPI box parsing the cleartext-inside-TLS upgrade
    // (e.g. an active prober) sees an ordinary request.
    req += "Origin: https://" + host_hdr + "\r\n";
    req += "User-Agent: Mozilla/5.0 (FinBit)\r\n";
    req += "\r\n";

    up.request.assign(req.begin(), req.end());
    return up;
}

ClientHandshakeParser::ClientHandshakeParser(std::string expected_key)
    : expected_accept_(compute_accept(expected_key)) {}

ClientHandshakeParser::Status
ClientHandshakeParser::feed(std::span<const std::uint8_t> bytes) {
    buf_.insert(buf_.end(), bytes.begin(), bytes.end());
    static const std::uint8_t terminator[] = {'\r', '\n', '\r', '\n'};
    auto it = std::search(buf_.begin(), buf_.end(),
                          std::begin(terminator), std::end(terminator));
    if (it == buf_.end()) {
        if (buf_.size() > 16384) {
            reason_ = "response headers too large";
            return Status::kRejected;
        }
        return Status::kNeedMore;
    }
    headers_end_ = static_cast<std::size_t>((it - buf_.begin()) + 4);
    const std::string headers(buf_.begin(), buf_.begin() + headers_end_);

    // Status line must be "HTTP/1.1 101 ...".
    if (headers.compare(0, 5, "HTTP/") != 0 ||
        headers.find(" 101 ") == std::string::npos) {
        reason_ = "server did not return 101 Switching Protocols";
        return Status::kRejected;
    }
    if (!icontains(headers, "Upgrade: websocket")) {
        reason_ = "missing Upgrade: websocket in response";
        return Status::kRejected;
    }
    // Verify Sec-WebSocket-Accept matches what we expect for our key.
    const std::string needle = "sec-websocket-accept:";
    std::string lower_h = headers;
    for (auto& c : lower_h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const auto pos = lower_h.find(needle);
    if (pos == std::string::npos) {
        reason_ = "missing Sec-WebSocket-Accept";
        return Status::kRejected;
    }
    const auto eol = headers.find("\r\n", pos);
    const std::string got =
        trim_ws(headers.substr(pos + needle.size(), eol - pos - needle.size()));
    if (expected_accept_.empty() || got != expected_accept_) {
        reason_ = "Sec-WebSocket-Accept mismatch";
        return Status::kRejected;
    }
    return Status::kAccepted;
}

namespace {

// Common framing for masked client frames. opcode: 0x2 binary, 0x8 close.
std::vector<std::uint8_t> build_masked_frame(std::uint8_t opcode,
                                             std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>(0x80 | opcode));  // FIN + opcode
    const std::size_t len = payload.size();
    if (len < 126) {
        out.push_back(static_cast<std::uint8_t>(0x80 | len));  // MASK bit + len
    } else if (len <= 0xFFFF) {
        out.push_back(static_cast<std::uint8_t>(0x80 | 126));
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(len & 0xff));
    } else {
        out.push_back(static_cast<std::uint8_t>(0x80 | 127));
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<std::uint8_t>((len >> (i * 8)) & 0xff));
        }
    }
    std::array<std::uint8_t, 4> mask{};
    if (sodium_init() >= 0) {
        randombytes_buf(mask.data(), mask.size());
    }
    out.insert(out.end(), mask.begin(), mask.end());
    const std::size_t body_off = out.size();
    out.resize(body_off + len);
    for (std::size_t i = 0; i < len; ++i) {
        out[body_off + i] = static_cast<std::uint8_t>(payload[i] ^ mask[i & 3]);
    }
    return out;
}

}  // namespace

std::vector<std::uint8_t> build_client_binary_frame(std::span<const std::uint8_t> payload) {
    return build_masked_frame(0x2, payload);
}

std::vector<std::uint8_t> build_client_close_frame() {
    return build_masked_frame(0x8, {});
}

void FrameParser::feed(std::span<const std::uint8_t> bytes) {
    if (!error_.empty()) return;
    buf_.insert(buf_.end(), bytes.begin(), bytes.end());
}

FrameParser::PopStatus FrameParser::try_pop(std::vector<std::uint8_t>& out) {
    if (!error_.empty()) return PopStatus::kError;
    while (true) {
        if (buf_.size() < 2) return PopStatus::kNeedMore;
        const std::uint8_t b0 = buf_[0];
        const std::uint8_t b1 = buf_[1];
        const bool fin    = (b0 & 0x80) != 0;
        const std::uint8_t opcode = b0 & 0x0f;
        const bool mask = (b1 & 0x80) != 0;
        // Direction enforcement: client→server frames MUST be masked
        // (RFC 6455 §5.1); server→client frames MUST NOT be. A server
        // parser (expect_masked_=true) rejects unmasked input; a client
        // parser (expect_masked_=false) handles either but server frames
        // are normally unmasked.
        if (expect_masked_ && !mask) {
            error_ = "client frame missing mask";
            return PopStatus::kError;
        }
        std::uint64_t payload_len = b1 & 0x7f;
        std::size_t header_len = 2;
        if (payload_len == 126) {
            if (buf_.size() < header_len + 2) return PopStatus::kNeedMore;
            payload_len = (static_cast<std::uint64_t>(buf_[header_len]) << 8) |
                          static_cast<std::uint64_t>(buf_[header_len + 1]);
            header_len += 2;
        } else if (payload_len == 127) {
            if (buf_.size() < header_len + 8) return PopStatus::kNeedMore;
            payload_len = 0;
            for (int i = 0; i < 8; ++i) {
                payload_len = (payload_len << 8) |
                              static_cast<std::uint64_t>(buf_[header_len + i]);
            }
            header_len += 8;
        }
        if (payload_len > kMaxMessageBytes) {
            error_ = "frame payload too large";
            return PopStatus::kError;
        }
        const std::size_t mask_bytes = mask ? 4 : 0;
        if (buf_.size() < header_len + mask_bytes + payload_len) return PopStatus::kNeedMore;
        std::uint8_t mask_key[4] = {0, 0, 0, 0};
        if (mask) {
            mask_key[0] = buf_[header_len];
            mask_key[1] = buf_[header_len + 1];
            mask_key[2] = buf_[header_len + 2];
            mask_key[3] = buf_[header_len + 3];
            header_len += 4;
        }
        std::vector<std::uint8_t> payload(payload_len);
        for (std::uint64_t i = 0; i < payload_len; ++i) {
            payload[i] = static_cast<std::uint8_t>(buf_[header_len + i] ^ mask_key[i & 3]);
        }
        // Consume.
        buf_.erase(buf_.begin(),
                   buf_.begin() + static_cast<std::ptrdiff_t>(header_len + payload_len));

        // Control frames.
        if (opcode == 0x8) return PopStatus::kClose;        // close
        if (opcode == 0x9) {                                  // ping — ignore for now
            continue;
        }
        if (opcode == 0xA) continue;                          // pong — ignore

        // Data frames: 0x1=text, 0x2=binary, 0x0=continuation.
        if (opcode == 0x0 && !in_fragment_) {
            error_ = "continuation without prior data frame";
            return PopStatus::kError;
        }
        if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
            if (opcode != 0x0) {
                partial_.clear();
                in_fragment_ = true;
            }
            partial_.insert(partial_.end(), payload.begin(), payload.end());
            if (partial_.size() > kMaxMessageBytes) {
                error_ = "fragmented message too large";
                return PopStatus::kError;
            }
            if (fin) {
                in_fragment_ = false;
                out = std::move(partial_);
                partial_.clear();
                return PopStatus::kFrameReady;
            }
            continue;
        }
        error_ = "unknown opcode";
        return PopStatus::kError;
    }
}

}  // namespace fb::net::ws
