// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// HKDF-SHA256 (RFC 5869) implemented on top of libsodium's HMAC-SHA256.
//
// Why we don't just call libsodium's crypto_kdf_hkdf_sha256_*:
//   * Those symbols were added in libsodium 1.0.19 (Aug 2023).
//   * Ubuntu 24.04 (the CI runner — and a common deploy target) ships
//     libsodium 1.0.18, which doesn't have them.
//   * Argon2id, Ed25519, X25519, AEAD primitives all DO ship in 1.0.18.
//   * crypto_auth_hmacsha256 — the only primitive HKDF actually needs —
//     has been in libsodium since forever.
//
// Implementing HKDF in ~30 lines on HMAC is the right move: removes a
// version dependency without giving up any cryptographic property.
// Output is byte-identical to libsodium's HKDF and to RFC 5869.

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace fb::crypto {

// HKDF-SHA256 output size for the extract step is fixed (the HMAC tag
// width). Callers that previously used crypto_kdf_hkdf_sha256_KEYBYTES
// can use kHkdfSha256Bytes instead.
inline constexpr std::size_t kHkdfSha256Bytes = 32;

using HkdfPrk = std::array<std::uint8_t, kHkdfSha256Bytes>;

// HKDF-Extract(salt, IKM) -> PRK. Empty salt is allowed; treated as a
// 32-byte zero block per RFC 5869 §2.2.
[[nodiscard]] HkdfPrk hkdf_extract(std::span<const std::uint8_t> salt,
                                    std::span<const std::uint8_t> ikm);

// HKDF-Expand(PRK, info, L) -> okm of length L. L must be in [1, 8160]
// (RFC 5869's 255 * HashLen ceiling). Throws std::invalid_argument on
// out-of-range L.
[[nodiscard]] std::vector<std::uint8_t> hkdf_expand(const HkdfPrk& prk,
                                                     std::span<const std::uint8_t> info,
                                                     std::size_t okm_len);

}  // namespace fb::crypto
