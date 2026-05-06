// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/host.hpp"

#include <stdexcept>

// =============================================================================
// PHASE 0 STUB. See host.hpp.
//
// Phase 5 wiring options:
//
//   Option A (preferred):  cpp-libp2p (Soramitsu)
//     - vendored or via vcpkg (cpp-libp2p is in vcpkg as `cpp-libp2p`)
//     - libp2p::Host implements both KadDHT and Gossipsub
//     - Pull libp2p Identity from the Ed25519 key supplied to make_p2p_host
//
//   Option B (fallback):   libtorrent DHT + custom gossip
//     - libtorrent has a battle-tested mainline DHT (Kademlia)
//     - Roll a small gossipsub-equivalent on top of fb::net::IoLoop
//     - Better support on mobile, smaller binary, but more code to own
//
// Rate limiting + carry-credit gating MUST live at this layer (the same
// per-pubkey token bucket the server uses).
// =============================================================================

namespace fb::p2p {

std::unique_ptr<IP2PHost> make_p2p_host(std::span<const std::uint8_t, 32>) {
    throw std::runtime_error(
        "p2p::make_p2p_host: not implemented (Phase 5 — needs cpp-libp2p or libtorrent DHT dep)");
}

}  // namespace fb::p2p
