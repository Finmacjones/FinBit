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
#include <map>
#include <set>
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

// ---------------------------------------------------------------------------
// Lever C — selective video forwarding plan (docs/serverless-group-calls.md).
//
// A forwarder can't relay 24 full-res videos (≈276 Mbps). It doesn't need
// to: relay HIGH res only for the few active speakers, a low-res THUMBNAIL
// for the next tier, and DROP the rest (audio is always forwarded — cheap).
// This decides, from per-sender audio RMS (dBFS; the active-speaker proxy),
// which quality each sender's *video* gets. Deterministic (ties by key).
// ---------------------------------------------------------------------------
enum class VideoQuality { kDrop, kThumbnail, kHigh };

[[nodiscard]] std::map<std::string, VideoQuality> plan_forwarded_video(
    const std::map<std::string, double>& levels,
    std::size_t max_high, std::size_t max_thumbnail, double floor_db);

// ---------------------------------------------------------------------------
// Lever D — cascade distribution tree (docs/serverless-group-calls.md).
//
// One forwarder caps out around its uplink; spread the load across a
// shallow fan-out tree so no node carries O(N²). Each node forwards to at
// most `fanout` children; strongest nodes (highest uplink_class) sit near
// the root to keep the tree shallow and reliable. Deterministic: sorted by
// (uplink_class desc, pubkey asc), assigned breadth-first.
// ---------------------------------------------------------------------------
struct TreeNode {
    std::string pubkey;
    std::string parent;     // "" for the root
    int         depth = 0;  // root = 0
};

// Returns one TreeNode per input candidate (root first, then BFS order).
// `fanout` is clamped to ≥1. Empty input → empty tree.
[[nodiscard]] std::vector<TreeNode> build_distribution_tree(
    const std::vector<ForwarderCandidate>& nodes, std::size_t fanout);

// ---------------------------------------------------------------------------
// Forwarder wiring plan (§4, docs/gstreamer-relay-spec.md).
//
// The elected forwarder receives each leaf's single audio stream and fans it
// to every OTHER leaf — i.e. the forwarding set is all ordered pairs of
// distinct leaves. `ForwarderRouting` tracks the live leaf set and yields the
// EDGE DELTAS to wire/tear-down on each join/leave, which is exactly what the
// dynamic GStreamer graph (tees + per-subscriber payloader branches) needs.
//
// This is the pure, deterministic brain of the SFU graph — separated from the
// GStreamer "muscle" (RoomForwarder) so the routing can be unit-tested without
// media hardware.
// ---------------------------------------------------------------------------

// A directed forwarding edge: leaf `src`'s inbound stream is relayed out to
// leaf `sub`'s connection. (`src` != `sub`; audio is bidirectional, so a pair
// of leaves yields two edges.)
struct ForwardEdge {
    std::string src;
    std::string sub;
    bool operator==(const ForwardEdge& o) const {
        return src == o.src && sub == o.sub;
    }
    // Deterministic ordering (src, then sub) for stable delta vectors.
    bool operator<(const ForwardEdge& o) const {
        return src != o.src ? src < o.src : sub < o.sub;
    }
};

class ForwarderRouting {
public:
    // Add a leaf. Returns the NEW edges to wire up: {leaf→s : existing s} ∪
    // {p→leaf : existing p} (sorted, deterministic). Re-adding an existing
    // leaf is a no-op and returns {}.
    std::vector<ForwardEdge> add_leaf(const std::string& leaf);

    // Remove a leaf. Returns the edges to TEAR DOWN: every edge whose src or
    // sub is `leaf` (sorted). Removing an unknown leaf returns {}.
    std::vector<ForwardEdge> remove_leaf(const std::string& leaf);

    // The full current edge set = all ordered pairs of distinct leaves.
    [[nodiscard]] std::vector<ForwardEdge> edges() const;

    // Leaves that receive `src`'s stream (everyone but `src`); empty if `src`
    // isn't a leaf. Sorted.
    [[nodiscard]] std::vector<std::string> subscribers_of(
        const std::string& src) const;

    [[nodiscard]] std::vector<std::string> leaves() const;   // sorted
    [[nodiscard]] std::size_t leaf_count() const;
    [[nodiscard]] bool has_leaf(const std::string& leaf) const;

private:
    std::set<std::string> leaves_;
};

}  // namespace fb::media
