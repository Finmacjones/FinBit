// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Real-time media (voice, video, screen-share) — Phase 2/3 scaffolding.
//
// FinBit pipes media through Google libwebrtc and applies SFrame at the
// encoded-frame layer so the SFU sees only ciphertext. SFrame keys are
// derived from the channel's MLS group secret (see crypto/mls_facade.hpp).
//
// PHASE 0 STATUS: stubs throw NotImplemented. Phase 2 wires this up by:
//   1. building libwebrtc against a pinned milestone (e.g. M122) — see
//      scripts/build-libwebrtc.sh (TODO: write that script)
//   2. exposing PeerConnectionFactory + PeerConnectionInterface behind these
//      types (kept abstract here so the rest of the code never sees libwebrtc
//      headers — they're enormous and slow to compile)
//   3. wiring the MediaSignal Envelope inner-message type for SDP/ICE exchange
//   4. installing an EncodedFrameTransform that calls SFrame::seal/open
// =============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace fb::media {

enum class TrackKind { kAudio, kVideo, kScreenShare };

struct MediaTrack {
    TrackKind   kind;
    std::string label;
};

class PeerConnection {
public:
    virtual ~PeerConnection() = default;

    // Add a local track to the call.
    virtual void add_local_track(const MediaTrack& t) = 0;

    // Wire SFrame keys from the MLS group's exporter secret. Caller refreshes
    // on every group change (member add/remove).
    virtual void install_sframe_key(std::span<const std::uint8_t, 32> key,
                                    std::uint32_t epoch) = 0;

    // SDP / ICE signaling — opaque blobs that travel inside MediaSignal
    // Envelope inner messages.
    virtual std::vector<std::uint8_t> create_offer() = 0;
    virtual void                      apply_answer(std::span<const std::uint8_t> sdp) = 0;
    virtual void                      add_ice_candidate(std::span<const std::uint8_t> ice) = 0;

    // Callback when a remote track arrives.
    using OnTrack = std::function<void(const MediaTrack&)>;
    virtual void set_on_track(OnTrack cb) = 0;
};

// Factory — returns a libwebrtc-backed implementation in Phase 2.
[[nodiscard]] std::unique_ptr<PeerConnection> create_peer_connection();

// SFrame primitives surfaced for testing without libwebrtc. SFrame seals each
// encoded video/audio frame independently with a key derived from
// `base_key + epoch + counter`. Returns sealed bytes; identical key + counter
// always produce identical output (deterministic for testability).
//
// SPEC: draft-ietf-sframe-enc (latest IETF SFrame draft).
[[nodiscard]] std::vector<std::uint8_t> sframe_seal(
    std::span<const std::uint8_t, 32> base_key, std::uint32_t epoch, std::uint64_t counter,
    std::span<const std::uint8_t> frame);

}  // namespace fb::media
