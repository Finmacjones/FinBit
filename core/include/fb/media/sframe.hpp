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

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace fb::media {

// ---------------------------------------------------------------------------
// Group (forwarded-room) keying — Lever B, docs/serverless-group-calls.md.
//
// 1:1 / full-mesh calls key SFrame per *pair* (X3DH(pair) ‖ call_id). That
// can't work once a peer-forwarder fans ONE sender's sealed frames out to
// every receiver: all receivers need that sender's key. So a forwarded room
// shares a 32-byte `room_secret` (from the MLS exporter — mls::State::
// do_export — or a distributed random key for SenderKeys channels) and every
// member derives the SAME per-sender base key from it:
//
//   K_sender = HKDF-SHA256(extract(salt=nil, room_secret),
//                          info = "FinBit-SFrame-room-v1" ‖ sender_pubkey
//                                 ‖ be32(epoch), L = 32)
//
// A publisher seals with K_self; any receiver derives K_sender to open that
// publisher's frames; the forwarder, holding no key, relays sealed bytes
// blindly. `epoch` is the room membership epoch (RoomRoster.sframe_epoch) —
// bumping it (with a rotated room_secret) re-keys the room on join/leave.
// The result plugs straight into sframe_seal_v1 / sframe_open_v1 as base_key.
// ---------------------------------------------------------------------------
[[nodiscard]] std::array<std::uint8_t, 32> derive_room_sframe_key(
    std::span<const std::uint8_t, 32> room_secret,
    std::span<const std::uint8_t> sender_pubkey,
    std::uint32_t epoch);

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
