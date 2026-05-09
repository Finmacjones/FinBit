// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// UsernameGossip — peer-to-peer sync of the username log.
//
// Drives ClaimsSinceRequest / ClaimsSinceResponse exchanges over a
// caller-supplied transport. Two roles per pair of peers:
//
//   sync_with(peer, since_ms) — the LOCAL peer asks `peer` to send
//     every claim it has with timestamp_ms > since_ms. The peer
//     replies with a ClaimsSinceResponse; we feed each claim into
//     our local UsernameLog (idempotent — duplicates are accepted as
//     kAlreadyKnown). Useful as a periodic anti-entropy pass: ask
//     each peer for "everything since the last time we synced with
//     YOU", which keeps the per-peer high-watermark stable across
//     restarts.
//
//   on_message(from_peer, wire_bytes) — single inbound entry point.
//     Parses an IdentityGossipMessage envelope. For requests we
//     emit a paginated response (cap = kClaimsPageMax per round).
//     For responses we merge claims into the log via append_claim.
//
// Same transport-agnostic shape as DhtNode: caller supplies the
// SendCallback. Tests use a loopback bridge.
// =============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace fb::p2p { struct PeerInfo; }
namespace fb::identity { class UsernameLog; }
namespace fb::proto { class IdentityGossipMessage; }

namespace fb::identity {

// Per-batch cap when responding to ClaimsSinceRequest. Keeps per-RPC
// payload bounded; if a peer is many epochs behind, the requester
// must paginate by re-issuing sync_with using max_seen_ms from the
// previous response. Conservative default — bigger gives fewer
// round trips at the cost of more memory per response.
constexpr std::size_t kClaimsPageMax = 256;

using GossipSendCallback =
    std::function<void(const fb::p2p::PeerInfo& peer,
                       std::span<const std::uint8_t> wire_bytes)>;

class UsernameGossip {
public:
    UsernameGossip(UsernameLog& log, GossipSendCallback send);
    ~UsernameGossip();
    UsernameGossip(const UsernameGossip&)            = delete;
    UsernameGossip& operator=(const UsernameGossip&) = delete;

    // Initiate a sync against `peer` for everything strictly newer
    // than since_ms. Pass 0 to fetch the entire log (useful on first
    // contact). Returns the request_id (16 bytes) that the matching
    // response will echo back.
    [[nodiscard]] std::vector<std::uint8_t> sync_with(
        const fb::p2p::PeerInfo& peer, std::uint64_t since_ms);

    // Inbound dispatch.
    void on_message(const fb::p2p::PeerInfo& from_peer,
                    std::span<const std::uint8_t> wire_bytes);

    // Diagnostics: how many distinct claims the local log has
    // accepted via gossip during this UsernameGossip's lifetime
    // (kAccepted only — kAlreadyKnown duplicates don't count).
    [[nodiscard]] std::size_t accepted_via_gossip() const noexcept;

private:
    struct Impl;
    UsernameLog&                    log_;
    GossipSendCallback              send_;
    std::unique_ptr<Impl>           impl_;
};

}  // namespace fb::identity
