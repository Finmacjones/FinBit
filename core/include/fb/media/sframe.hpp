// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// SFrame primitive — simplified draft-ietf-sframe variant.
//
// Real SFrame (the IETF draft) is what libwebrtc plugs into via its
// EncodedFrameTransform interface so the SFU sees only ciphertext frames. The
// FinBit Phase 2/3 video/audio path reuses *exactly* this primitive — once
// libwebrtc is integrated, the EncodedFrameTransform implementation calls
// fb::media::sframe_seal / sframe_open per encoded frame.
//
// Per-frame key derivation (simplified vs the full spec but consistent):
//
//   per_frame_key   = HKDF-SHA256(base_key, salt=nil,
//                                 info = "FB-SFrame-key" || epoch || counter,
//                                 L = 32)
//   per_frame_nonce = HKDF-SHA256(base_key, salt=nil,
//                                 info = "FB-SFrame-nonce" || epoch || counter,
//                                 L = 12)
//   ciphertext      = AES-256-GCM(plaintext, per_frame_key, per_frame_nonce,
//                                  aad = epoch || counter)
//
// The wire format produced by sframe_seal is:
//   [u32 BE epoch][u64 BE counter][ciphertext+tag]
//
// `base_key` rotates whenever the MLS / SenderKeys group secret changes
// (member add/remove, periodic re-key). `counter` MUST monotonically increase
// per (sender, epoch); receivers reject decreases with std::nullopt.
//
// This is NOT byte-identical to draft-ietf-sframe (which has a more compact
// counter encoding and several KDF labels FinBit doesn't need today). When
// libwebrtc is wired in we'll align on the IETF labels exactly so we can
// interoperate with other SFrame implementations.
// =============================================================================

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace fb::media {

// Seal a single encoded frame. Throws on AEAD failure (which only happens if
// AES-NI is unavailable on the running CPU — see fb::crypto::aes256gcm_hw_available).
[[nodiscard]] std::vector<std::uint8_t> sframe_seal_v1(
    std::span<const std::uint8_t, 32> base_key, std::uint32_t epoch, std::uint64_t counter,
    std::span<const std::uint8_t> plaintext);

// Open a sealed frame. Returns the plaintext on success, std::nullopt on
// tag mismatch / malformed header.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> sframe_open_v1(
    std::span<const std::uint8_t, 32> base_key, std::span<const std::uint8_t> sealed);

}  // namespace fb::media
