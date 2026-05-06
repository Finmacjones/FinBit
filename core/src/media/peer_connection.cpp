// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/peer_connection.hpp"

#include <stdexcept>

// =============================================================================
// PHASE 0 STUB. See peer_connection.hpp.
// =============================================================================

namespace fb::media {

std::unique_ptr<PeerConnection> create_peer_connection() {
    throw std::runtime_error(
        "media::create_peer_connection: not implemented (Phase 2 — needs libwebrtc dep)");
}

std::vector<std::uint8_t> sframe_seal(std::span<const std::uint8_t, 32> /*base_key*/,
                                      std::uint32_t /*epoch*/, std::uint64_t /*counter*/,
                                      std::span<const std::uint8_t> /*frame*/) {
    throw std::runtime_error(
        "media::sframe_seal: not implemented (Phase 2 — needs SFrame impl on libsodium AEAD)");
}

}  // namespace fb::media
