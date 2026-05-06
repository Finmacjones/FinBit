// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace fb::crypto {

// AES-256-GCM sizes — matches libsodium crypto_aead_aes256gcm_*BYTES.
inline constexpr std::size_t kAesKeyBytes   = 32;
inline constexpr std::size_t kAesNonceBytes = 12;
inline constexpr std::size_t kAesTagBytes   = 16;

// XChaCha20-Poly1305 sizes — matches libsodium crypto_aead_xchacha20poly1305_ietf_*BYTES.
// Same key + tag size as AES-GCM, but a 24-byte nonce (random nonce reuse
// is statistically negligible at any realistic scale).
inline constexpr std::size_t kXChaChaKeyBytes   = 32;
inline constexpr std::size_t kXChaChaNonceBytes = 24;
inline constexpr std::size_t kXChaChaTagBytes   = 16;

using AeadKey   = std::array<std::uint8_t, kAesKeyBytes>;
using AeadNonce = std::array<std::uint8_t, kAesNonceBytes>;
using XChaChaNonce = std::array<std::uint8_t, kXChaChaNonceBytes>;

// Algorithm identifier carried in Envelope.aead_alg. Mirrors fb::config::aead_alg.
enum class AeadAlg : std::uint32_t {
    kAes256Gcm        = 1,
    kXChaCha20Poly1305 = 2,  // reserved, not yet implemented
};

// Returns true if the runtime CPU supports AES-256-GCM acceleration (AES-NI on
// x86_64, ARMv8 crypto extensions). libsodium refuses to encrypt with AES-256-GCM
// if this returns false — there is no constant-time software implementation in
// the library. Callers without AES-NI can fall back to XChaCha20-Poly1305 by
// passing AeadAlg::kXChaCha20Poly1305 (always-available, software-only,
// statistically-unique random nonces via XChaCha20's 192-bit nonce space).
[[nodiscard]] bool aes256gcm_hw_available() noexcept;

// Always available (libsodium ships a portable software impl).
[[nodiscard]] inline bool xchacha20poly1305_available() noexcept { return true; }

// XChaCha20 random 24-byte nonce — statistically unique at any practical scale.
[[nodiscard]] XChaChaNonce random_xchacha_nonce();

// XChaCha20-Poly1305 encrypt/decrypt — same shape as the AES variants but
// with a 24-byte nonce. AeadAlg discriminator is implied by the entry point.
[[nodiscard]] std::vector<std::uint8_t> xchacha20_encrypt(
    const AeadKey& key, const XChaChaNonce& nonce,
    std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> aad);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> xchacha20_decrypt(
    const AeadKey& key, const XChaChaNonce& nonce,
    std::span<const std::uint8_t> ciphertext_with_tag, std::span<const std::uint8_t> aad);

// Derive a fresh random 32-byte AEAD key.
[[nodiscard]] AeadKey random_key();

// Derive a fresh random 12-byte nonce. Callers MUST never reuse a nonce with
// the same key — for ratchet messages the nonce is derived deterministically
// from the message counter, not via random_nonce.
[[nodiscard]] AeadNonce random_nonce();

// AEAD encrypt. Returns ciphertext || tag (combined mode). Throws on failure
// (which for AES-256-GCM only happens if hardware acceleration is unavailable
// or arguments are malformed).
[[nodiscard]] std::vector<std::uint8_t> aead_encrypt(AeadAlg alg, const AeadKey& key,
                                                     const AeadNonce& nonce,
                                                     std::span<const std::uint8_t> plaintext,
                                                     std::span<const std::uint8_t> aad);

// AEAD decrypt. Returns plaintext on success, std::nullopt on tag mismatch
// (forged or corrupted ciphertext). Throws only on invalid argument shapes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> aead_decrypt(
    AeadAlg alg, const AeadKey& key, const AeadNonce& nonce,
    std::span<const std::uint8_t> ciphertext_with_tag, std::span<const std::uint8_t> aad);

}  // namespace fb::crypto
