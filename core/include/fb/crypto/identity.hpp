// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace fb::crypto {

// Ed25519 sizes — matches libsodium crypto_sign_*BYTES.
inline constexpr std::size_t kIdentityPubKeyBytes = 32;
inline constexpr std::size_t kIdentitySecKeyBytes = 64;
inline constexpr std::size_t kIdentitySigBytes    = 64;
inline constexpr std::size_t kIdentitySeedBytes   = 32;

using PubKey  = std::array<std::uint8_t, kIdentityPubKeyBytes>;
using SecKey  = std::array<std::uint8_t, kIdentitySecKeyBytes>;
using Sig     = std::array<std::uint8_t, kIdentitySigBytes>;
using Seed    = std::array<std::uint8_t, kIdentitySeedBytes>;

// Long-term Ed25519 identity. Owns secret key in a sodium-allocated, mlocked
// buffer that zeroes on destruction.
class Identity {
public:
    // Generate a fresh random identity. Calls sodium_init() on first use.
    [[nodiscard]] static Identity generate();

    // Reproduce an identity from a 32-byte seed (for deterministic tests
    // and key-derivation flows; never use a low-entropy seed in production).
    [[nodiscard]] static Identity from_seed(std::span<const std::uint8_t, kIdentitySeedBytes> seed);

    Identity(const Identity&)            = delete;
    Identity& operator=(const Identity&) = delete;
    Identity(Identity&&) noexcept;
    Identity& operator=(Identity&&) noexcept;
    ~Identity();

    [[nodiscard]] const PubKey& public_key() const noexcept { return pub_; }
    [[nodiscard]] std::span<const std::uint8_t, kIdentitySecKeyBytes> secret_key() const noexcept;

    // Detached Ed25519 signature over `message`.
    [[nodiscard]] Sig sign(std::span<const std::uint8_t> message) const;

    // Verify a detached Ed25519 signature against this identity's public key.
    [[nodiscard]] static bool verify(const PubKey& pubkey,
                                     std::span<const std::uint8_t> message,
                                     const Sig& signature) noexcept;

    // Short, human-readable fingerprint of the public key. Currently 10
    // characters of base32 over the first 6 bytes of BLAKE2b-160(pubkey) —
    // grouped as XXXXX-XXXXX. Stable for a given pubkey.
    [[nodiscard]] static std::string fingerprint(const PubKey& pubkey);
    [[nodiscard]] std::string fingerprint() const { return fingerprint(pub_); }

private:
    Identity() = default;
    PubKey pub_{};
    std::uint8_t* sec_locked_ = nullptr;  // sodium_malloc'd, mlocked, length=64
};

// Free helpers for serialization. Public keys are not secret; secret keys
// must be persisted only via Identity's at-rest encryption path (TODO).
[[nodiscard]] std::string         pubkey_to_base64(const PubKey& pubkey);
[[nodiscard]] bool                pubkey_from_base64(std::string_view encoded, PubKey& out) noexcept;

// Derive a 64-byte ML-KEM seed deterministically from a 32-byte Ed25519
// identity seed. Used to give every identity a stable post-quantum keypair
// without persisting a separate file: the PQ keypair is recomputable from
// the same seed material the rest of the identity flows from.
//
// HKDF-SHA256 extract-then-expand with a FinBit-versioned info string
// ("FinBit-PQ-seed-v1") so a future bump (e.g. ML-KEM-1024) gets a
// distinct derivation and doesn't collide with the v1 keypair.
[[nodiscard]] std::array<std::uint8_t, 64> derive_pq_seed_from_identity_seed(
    std::span<const std::uint8_t, kIdentitySeedBytes> seed);

// Derive a 32-byte FIPS-204 ML-DSA-65 seed (ξ) deterministically from the
// Ed25519 identity seed. Parallel to derive_pq_seed_from_identity_seed but
// for signing — distinct info string ("FinBit-PQSIG-seed-v1") keeps the
// two derivations domain-separated so the PQ-sig keypair is independent
// of the PQ-KEM keypair even though both root in the same Ed25519 seed.
[[nodiscard]] std::array<std::uint8_t, 32> derive_pq_sig_seed_from_identity_seed(
    std::span<const std::uint8_t, kIdentitySeedBytes> seed);

}  // namespace fb::crypto
