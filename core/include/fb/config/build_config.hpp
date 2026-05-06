// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace fb::config {

// =============================================================================
// PLACEHOLDER SERVER URL — REPLACE BEFORE PRODUCTION DEPLOY
// =============================================================================
// FinBit clients reach the central relay/directory server at this URL during
// the centralized phase (Phase 0–4). After Phase 5 the URL still serves as the
// bootstrap endpoint for the P2P DHT.
//
// This value is a placeholder. To swap it, edit this constant — every other
// reference in the codebase reads `kDefaultServerUrl` rather than hard-coding
// the URL. The runtime can also override it via environment variable
// `FB_SERVER_URL` or the on-disk settings file.
//
// TODO(deploy): replace with the production server URL.
// =============================================================================
inline constexpr std::string_view kDefaultServerUrl = "https://server.example.invalid";

// Name of the env var that overrides kDefaultServerUrl at runtime.
inline constexpr std::string_view kServerUrlEnvVar = "FB_SERVER_URL";

// Network protocol version. Bump on any wire-incompatible change to envelope.proto
// or the inner message vocabulary.
inline constexpr std::uint32_t kProtocolVersion = 1;

// Threshold of active users at which the network transitions from centralized
// relay to P2P/decentralized operation. Below this the central server is the
// authoritative relay; above it the server is demoted to bootstrap + offline
// store and peers prefer direct connections.
inline constexpr std::uint64_t kDecentralizationThreshold = 10'000;

// AEAD algorithm identifiers that may appear in Envelope.aead_alg.
// Only kAeadAlgAes256Gcm is supported in the initial release; the field exists
// so additional ciphers (e.g. XChaCha20-Poly1305) can be negotiated later
// without a wire-protocol break.
namespace aead_alg {
inline constexpr std::uint32_t kAes256Gcm = 1;
inline constexpr std::uint32_t kXChaCha20Poly1305 = 2;  // reserved, not yet implemented
}  // namespace aead_alg

// Default rate-limit token bucket parameters applied per-pubkey at every relay
// hop. Both server (centralized) and peers (P2P) enforce these.
namespace ratelimit {
inline constexpr std::uint64_t kDefaultSustainedBytesPerSec = 50 * 1024;       // 50 KB/s
inline constexpr std::uint64_t kDefaultBurstBytes           = 500 * 1024;      // 500 KB
}  // namespace ratelimit

}  // namespace fb::config
