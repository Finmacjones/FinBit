// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Post-quantum KEM — ML-KEM-768 (FIPS-203).
//
// Provides the post-quantum half of FinBit's hybrid key exchange. Paired with
// the classical X25519 ECDH in `hybrid_kem.hpp` to defeat "harvest now,
// decrypt later" — a state-level adversary that records a ciphertext today
// cannot recover the session key with a future cryptographically-relevant
// quantum computer, because the X25519 shared secret was AND-mixed with the
// ML-KEM shared secret. Breaking the hybrid requires breaking BOTH.
//
// Why ML-KEM-768: NIST FIPS-203 final (Aug 2024). Sec-level 3 (~AES-192
// post-quantum). The 256 variant is overkill for chat at the cost of much
// larger pubkeys and ciphertexts; 512 is sec-level 1 (~AES-128 PQ) which we
// consider too low for the "fortify against governments" threat model.
//
// Why OpenSSL: OpenSSL 3.5+ ships ML-KEM-{512,768,1024} natively in the
// default provider (FIPS-203 conformant). No third-party PQ library to
// vendor or build. CMake already finds OpenSSL for TLS/DoH/ECH.
//
// Sizes (FIPS-203 §8 / OpenSSL):
//   * Public key:    1184 bytes
//   * Secret key:    2400 bytes
//   * Ciphertext:    1088 bytes
//   * Shared secret:   32 bytes
//
// Threading: all operations are stateless and reentrant. The OpenSSL EVP_PKEY
// objects are constructed per-call.
// =============================================================================

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace fb::crypto::pq {

inline constexpr std::size_t kMlKem768PubBytes = 1184;
inline constexpr std::size_t kMlKem768SecBytes = 2400;
inline constexpr std::size_t kMlKem768CtBytes  = 1088;
inline constexpr std::size_t kMlKem768SsBytes  =   32;

using MlKem768Pub = std::array<std::uint8_t, kMlKem768PubBytes>;
using MlKem768Sec = std::array<std::uint8_t, kMlKem768SecBytes>;
using MlKem768Ct  = std::array<std::uint8_t, kMlKem768CtBytes>;
using MlKem768Ss  = std::array<std::uint8_t, kMlKem768SsBytes>;

struct MlKem768Keypair {
    MlKem768Pub pub{};
    MlKem768Sec sec{};
};

struct MlKem768Encap {
    MlKem768Ct ct{};   // encapsulated key, sent on the wire to the holder of `sec`
    MlKem768Ss ss{};   // shared secret, kept by the sender
};

class PqError : public std::runtime_error {
 public:
    using std::runtime_error::runtime_error;
};

// True when the build's OpenSSL exposes ML-KEM-768 via the default provider.
// Used by call sites that want a soft-feature-check before forcing PQ-hybrid
// (a build against OpenSSL <3.5 will return false and throw on the calls below).
[[nodiscard]] bool ml_kem_768_available() noexcept;

// Fresh ML-KEM-768 keypair. Throws PqError if OpenSSL refuses (provider missing
// or RNG failure). Uses the OS CSPRNG via OpenSSL's RAND_bytes.
[[nodiscard]] MlKem768Keypair keygen_ml_kem_768();

// Deterministic ML-KEM-768 keypair derived from a 64-byte seed (FIPS-203
// §6.1 d || z). Same seed → byte-identical keypair across builds / hosts /
// invocations. The OpenSSL provider exposes this via OSSL_PKEY_PARAM
// "seed". Used to derive PQ identity material from FinBit's existing
// long-term Ed25519 seed — see fb::crypto::derive_pq_keypair_from_seed.
// Throws PqError on unsupported provider / OpenSSL failure.
inline constexpr std::size_t kMlKem768SeedBytes = 64;
[[nodiscard]] MlKem768Keypair keygen_ml_kem_768_from_seed(
    std::span<const std::uint8_t, kMlKem768SeedBytes> seed);

// Encapsulate against `peer_pub`. Returns (ciphertext, shared_secret).
// The ciphertext is shipped to the peer; the shared_secret is the local
// half of the KEM agreement (the peer recovers an identical ss via decap).
// Throws PqError on malformed pubkey or OpenSSL failure.
[[nodiscard]] MlKem768Encap encap_ml_kem_768(std::span<const std::uint8_t, kMlKem768PubBytes> peer_pub);

// Decapsulate `ct` using `my_sec`. Returns the recovered shared secret,
// which equals the `ss` the encapsulating party kept. Throws PqError on
// malformed inputs or OpenSSL failure. ML-KEM is IND-CCA2: a malformed
// ciphertext returns a pseudorandom-but-deterministic secret rather than
// an error (implicit rejection), so this function does NOT distinguish
// "tampered" from "valid"; mismatched secrets surface downstream as a
// failed AEAD decrypt — which is the safe FIPS-203 behavior.
[[nodiscard]] MlKem768Ss decap_ml_kem_768(std::span<const std::uint8_t, kMlKem768CtBytes> ct,
                                          std::span<const std::uint8_t, kMlKem768SecBytes> my_sec);

}  // namespace fb::crypto::pq
