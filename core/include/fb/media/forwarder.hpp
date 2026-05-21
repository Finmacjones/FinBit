// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Forwarder election + call topology for many-party calls without a
// dedicated SFU (Lever B, docs/serverless-group-calls.md).
//
// A room too big for full-mesh elects ONE participant (or a volunteer
// relay peer) to forward media: each leaf sends its stream once to the
// forwarder, which fans it out. SFrame keeps the forwarder blind — it
// relays sealed frames it can't read.
//
// Election must be DETERMINISTIC: every participant independently computes
// the *same* forwarder from the same roster (like the mesh glare-tiebreak),
// so no server or extra round-trip is needed. These functions are pure +
// unit-tested; the GStreamer media-relay pipeline that acts on the plan is
// the separate, hardware-tested piece.
// =============================================================================

#include <cstddef>
#include <string>
#include <vector>

namespace fb::media {

// A candidate forwarder = a room participant and how good a relay it is.
// `pubkey` is the raw 32-byte identity key (as a std::string of bytes).
struct ForwarderCandidate {
    std::string pubkey;
    int         uplink_class = 0;   // 0 leaf-only … 3 volunteer (higher better)
};

// Elect the room's forwarder, or "" to stay full-mesh.
//
// Rooms with fewer than `mesh_threshold` participants stay mesh (return
// ""). Otherwise the highest `uplink_class` wins; ties break on the
// lexicographically-smallest pubkey (deterministic across all peers). If
// no candidate is capable (every uplink_class == 0) the room also stays
// mesh — better a strained mesh than routing through a node that can't
// carry it.
[[nodiscard]] std::string elect_forwarder(
    const std::vector<ForwarderCandidate>& candidates,
    std::size_t mesh_threshold);

// The local node's resulting media topology given an elected forwarder.
struct ForwarderPlan {
    std::string              forwarder;          // "" = full mesh
    bool                     i_am_forwarder = false;
    bool                     mesh = true;        // true => dial all peers (mesh)
    std::vector<std::string> dial;               // peers to establish media to
};

// Compute what THIS node should do. `participants` includes self.
//   - forwarder == ""        → mesh: dial every other participant.
//   - forwarder == my_pubkey → I'm the forwarder: connect to everyone.
//   - otherwise              → I'm a leaf: connect only to the forwarder.
// `dial` is sorted for determinism.
[[nodiscard]] ForwarderPlan plan_topology(
    const std::vector<std::string>& participants,
    const std::string& my_pubkey,
    const std::string& forwarder);

}  // namespace fb::media
