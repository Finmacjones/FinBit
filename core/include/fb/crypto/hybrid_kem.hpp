// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Hybrid (classical + post-quantum) shared-secret combiner.
//
// Combines an X25519 ECDH shared secret with an ML-KEM-768 KEM shared secret
// into a single 32-byte hybrid secret that's secure as long as EITHER half is
// secure. The construction is HKDF-SHA256 in the "concat then extract+expand"
// style recommended by NIST SP 800-56C r2 and used by Signal's PQXDH and
// IETF's hybrid-design draft.
//
//   PRK   = HKDF-Extract(salt = "FinBit-hybrid-v1", IKM = ss_x25519 || ss_mlkem)
//   hyb   = HKDF-Expand(PRK, info = "FinBit hybrid X25519+ML-KEM-768", L = 32)
//
// Properties:
//   * Backward classical security: a polynomial-time adversary that breaks
//     ML-KEM but not X25519 cannot recover `hyb`.
//   * Forward PQ security: a CRQC-equipped adversary that breaks X25519
//     (Shor's algorithm) but not ML-KEM cannot recover `hyb`.
//   * Domain-separated from every other HKDF use in the codebase via the
//     literal "FinBit-hybrid-v1" salt + the "FinBit hybrid X25519+ML-KEM-768"
//     info string. Versioned on the salt so a future tier-bump (e.g.
//     ML-KEM-1024) is wire-distinguishable.
//
// "Harvest now, decrypt later" defense: an adversary that records the public
// X25519 share + the ML-KEM ciphertext today and gets a CRQC in 2040 still
// cannot recover `hyb`, because ML-KEM decapsulation requires the recipient's
// ML-KEM private key (which is post-quantum-secret). Adding this is the ONE
// censorship-resistance measure that cannot be applied retroactively — every
// ciphertext sent without it is permanently at risk.
// =============================================================================

#include <array>
#include <cstdint>
#include <span>

namespace fb::crypto::hybrid {

inline constexpr std::size_t kHybridSsBytes = 32;

using HybridSs = std::array<std::uint8_t, kHybridSsBytes>;

// Combine a 32-byte X25519 shared secret with a 32-byte ML-KEM-768 shared
// secret into a single 32-byte hybrid secret. Both inputs MUST be uniformly
// random (i.e. straight from the respective KEX/KEM); HKDF doesn't fix
// biased inputs.
[[nodiscard]] HybridSs combine_x25519_mlkem768(
    std::span<const std::uint8_t, 32> ss_x25519,
    std::span<const std::uint8_t, 32> ss_mlkem768);

}  // namespace fb::crypto::hybrid
