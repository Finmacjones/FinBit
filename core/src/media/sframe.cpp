// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/sframe.hpp"

#include <sodium.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "fb/crypto/aead.hpp"
#include "fb/crypto/hkdf.hpp"

namespace fb::media {
namespace {

constexpr std::string_view kInfoKey   = "FB-SFrame-key";
constexpr std::string_view kInfoNonce = "FB-SFrame-nonce";

void be_u32(std::uint32_t v, std::uint8_t* out) {
    out[0] = static_cast<std::uint8_t>((v >> 24) & 0xff);
    out[1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
    out[2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    out[3] = static_cast<std::uint8_t>(v & 0xff);
}
void be_u64(std::uint64_t v, std::uint8_t* out) {
    for (int i = 0; i < 8; ++i) out[i] = static_cast<std::uint8_t>((v >> (56 - 8 * i)) & 0xff);
}
std::uint32_t rd_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
std::uint64_t rd_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<std::uint64_t>(p[i]);
    return v;
}

void ensure_sodium() {
    static const int rc = sodium_init();
    if (rc < 0) throw std::runtime_error("libsodium init failed");
}

template <std::size_t Out>
std::array<std::uint8_t, Out> hkdf_expand_label(std::span<const std::uint8_t, 32> base,
                                                std::string_view label, std::uint32_t epoch,
                                                std::uint64_t counter) {
    // Build info = label || epoch || counter
    std::vector<std::uint8_t> info(label.size() + 4 + 8);
    std::memcpy(info.data(), label.data(), label.size());
    be_u32(epoch, info.data() + label.size());
    be_u64(counter, info.data() + label.size() + 4);

    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(base.data(), base.size()));
    auto vec = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(info.data(), info.size()), Out);
    std::array<std::uint8_t, Out> out{};
    std::memcpy(out.data(), vec.data(), Out);
    return out;
}

}  // namespace

std::array<std::uint8_t, 32> derive_room_sframe_key(
    std::span<const std::uint8_t, 32> room_secret,
    std::span<const std::uint8_t> sender_pubkey, std::uint32_t epoch) {
    ensure_sodium();
    // info = "FinBit-SFrame-room-v1" || sender_pubkey || be32(epoch)
    constexpr std::string_view kLabel = "FinBit-SFrame-room-v1";
    std::vector<std::uint8_t> info(kLabel.size() + sender_pubkey.size() + 4);
    std::memcpy(info.data(), kLabel.data(), kLabel.size());
    if (!sender_pubkey.empty()) {
        std::memcpy(info.data() + kLabel.size(), sender_pubkey.data(),
                    sender_pubkey.size());
    }
    be_u32(epoch, info.data() + kLabel.size() + sender_pubkey.size());

    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(room_secret.data(), room_secret.size()));
    auto vec = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(info.data(), info.size()), 32);
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), vec.data(), 32);
    return out;
}

std::vector<std::uint8_t> sframe_seal_v1(std::span<const std::uint8_t, 32> base_key,
                                         std::uint32_t epoch, std::uint64_t counter,
                                         std::span<const std::uint8_t> plaintext) {
    ensure_sodium();
    auto key_bytes = hkdf_expand_label<32>(base_key, kInfoKey, epoch, counter);
    auto nonce_bytes = hkdf_expand_label<12>(base_key, kInfoNonce, epoch, counter);

    fb::crypto::AeadKey key{};
    fb::crypto::AeadNonce nonce{};
    std::memcpy(key.data(), key_bytes.data(), 32);
    std::memcpy(nonce.data(), nonce_bytes.data(), 12);

    std::array<std::uint8_t, 12> aad{};
    be_u32(epoch, aad.data());
    be_u64(counter, aad.data() + 4);

    auto ct =
        fb::crypto::aead_encrypt(fb::crypto::AeadAlg::kAes256Gcm, key, nonce, plaintext,
                                 std::span<const std::uint8_t>(aad.data(), aad.size()));

    std::vector<std::uint8_t> out;
    out.reserve(12 + ct.size());
    out.resize(12);
    be_u32(epoch, out.data());
    be_u64(counter, out.data() + 4);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::optional<std::vector<std::uint8_t>> sframe_open_v1(std::span<const std::uint8_t, 32> base_key,
                                                        std::span<const std::uint8_t> sealed) {
    if (sealed.size() < 12) return std::nullopt;
    const std::uint32_t epoch = rd_u32(sealed.data());
    const std::uint64_t counter = rd_u64(sealed.data() + 4);

    auto key_bytes = hkdf_expand_label<32>(base_key, kInfoKey, epoch, counter);
    auto nonce_bytes = hkdf_expand_label<12>(base_key, kInfoNonce, epoch, counter);

    fb::crypto::AeadKey key{};
    fb::crypto::AeadNonce nonce{};
    std::memcpy(key.data(), key_bytes.data(), 32);
    std::memcpy(nonce.data(), nonce_bytes.data(), 12);

    std::array<std::uint8_t, 12> aad{};
    be_u32(epoch, aad.data());
    be_u64(counter, aad.data() + 4);

    return fb::crypto::aead_decrypt(
        fb::crypto::AeadAlg::kAes256Gcm, key, nonce,
        std::span<const std::uint8_t>(sealed.data() + 12, sealed.size() - 12),
        std::span<const std::uint8_t>(aad.data(), aad.size()));
}

}  // namespace fb::media
