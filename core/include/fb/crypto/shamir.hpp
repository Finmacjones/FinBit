// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Shamir Secret Sharing over GF(256) — for FinBit "social recovery."
//
// Splits a fixed-size secret (e.g. the 32-byte Ed25519 identity seed) into N
// shares where any M reconstruct, but M-1 reveal absolutely nothing about
// the secret (information-theoretic, independent of computational hardness
// assumptions — so this remains secure against any future cryptanalysis
// including a CRQC).
//
// Construction (byte-wise over GF(256), AES irreducible polynomial 0x11b):
//   For each secret byte s:
//     pick a random degree-(M-1) polynomial f(x) with f(0) = s
//     share i carries (i, f(i)) for i = 1..N
//   To recover s: Lagrange-interpolate f(0) from any M shares.
//
// On-wire share format (single share for a 32-byte secret = 33 bytes):
//   byte[0]      x-coordinate (1..255 — 0 reserved for the secret)
//   byte[1..32]  f(x) for each secret byte at this x
//
// USE CASE — social recovery: an identity owner runs
//   shamir::split(my_seed, M=3, N=5)
// and DMs each of the 5 resulting shares to a different trusted contact
// (in a one-shot, ratchet-encrypted envelope under each contact's session).
// If the device is later lost, the owner asks any 3 of those 5 contacts
// to relay their share back, runs
//   shamir::combine(shares)
// and recovers the seed. Each contact alone learns nothing — Shamir is
// information-theoretically secure as long as fewer than M shares are
// disclosed to any single party.
//
// LIMITATIONS:
//   * Total share size = secret_size * N (no compression / no Reed-Solomon
//     erasure encoding beyond the basic threshold scheme).
//   * No built-in integrity check — pass a fingerprint/checksum out of
//     band, or layer an AEAD (sealed envelope) per share. Shamir gives
//     confidentiality + threshold reconstruction, not authentication.
//   * x-coords must be 1..255 (GF(256) excludes 0). N <= 255.
// =============================================================================

#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace fb::crypto::shamir {

class ShamirError : public std::runtime_error {
 public:
    using std::runtime_error::runtime_error;
};

// One Shamir share: an explicit x-coordinate (1..255) and the polynomial
// evaluations (one byte per byte of the original secret). Total wire size =
// 1 + secret_size bytes.
struct Share {
    std::uint8_t              x = 0;
    std::vector<std::uint8_t> y;   // y.size() == original secret.size()
};

// Encode a Share as a single byte vector: [x | y...]. Convenient for
// transport (e.g. ratchet-seal each encoded share inside its own DM).
[[nodiscard]] std::vector<std::uint8_t> encode_share(const Share& s);

// Inverse of encode_share. Throws ShamirError on malformed input (empty
// or x == 0).
[[nodiscard]] Share decode_share(std::span<const std::uint8_t> bytes);

// Split `secret` into N shares where any M reconstruct. Constraints:
//   1 <= M <= N <= 255   and   M >= 1.
// Uses libsodium's CSPRNG for the polynomial coefficients. Throws
// ShamirError on out-of-range thresholds or empty secret.
[[nodiscard]] std::vector<Share> split(
    std::span<const std::uint8_t> secret,
    std::uint8_t threshold,         // M
    std::uint8_t total);            // N

// Reconstruct the secret from any M shares. All shares must have the same
// y.size() (same original secret length) and distinct nonzero x-coords.
// Throws ShamirError on inconsistent inputs.
//
// SAFETY: this does NOT verify that the recovered secret matches the
// original — Shamir doesn't carry integrity. Two valid-but-malicious
// shares can collude to produce a chosen wrong output. Callers MUST
// verify the recovered secret out-of-band (compare against a stored
// fingerprint, or wrap each share in an AEAD with the same key the
// secret derives).
[[nodiscard]] std::vector<std::uint8_t> combine(std::span<const Share> shares);

}  // namespace fb::crypto::shamir
