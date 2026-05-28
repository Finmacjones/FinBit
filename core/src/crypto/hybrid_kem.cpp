// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/hybrid_kem.hpp"

#include "fb/crypto/hkdf.hpp"

#include <array>
#include <cstring>

namespace fb::crypto::hybrid {

namespace {

constexpr char kSalt[] = "FinBit-hybrid-v1";
constexpr char kInfo[] = "FinBit hybrid X25519+ML-KEM-768";

}  // namespace

HybridSs combine_x25519_mlkem768(std::span<const std::uint8_t, 32> ss_x25519,
                                 std::span<const std::uint8_t, 32> ss_mlkem768) {
    // IKM = ss_x25519 || ss_mlkem768
    std::array<std::uint8_t, 64> ikm{};
    std::memcpy(ikm.data(),       ss_x25519.data(),    32);
    std::memcpy(ikm.data() + 32,  ss_mlkem768.data(),  32);

    // salt and info exclude the trailing NUL (HKDF treats them as opaque bytes).
    std::span<const std::uint8_t> salt(
        reinterpret_cast<const std::uint8_t*>(kSalt), sizeof(kSalt) - 1);
    std::span<const std::uint8_t> info(
        reinterpret_cast<const std::uint8_t*>(kInfo), sizeof(kInfo) - 1);

    HkdfPrk prk = hkdf_extract(salt, std::span<const std::uint8_t>(ikm.data(), ikm.size()));
    auto okm = hkdf_expand(prk, info, kHybridSsBytes);

    HybridSs out{};
    std::memcpy(out.data(), okm.data(), kHybridSsBytes);
    return out;
}

}  // namespace fb::crypto::hybrid
