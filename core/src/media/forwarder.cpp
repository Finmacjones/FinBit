// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/forwarder.hpp"

#include <algorithm>

namespace fb::media {

std::string elect_forwarder(const std::vector<ForwarderCandidate>& candidates,
                            std::size_t mesh_threshold) {
    if (candidates.size() < mesh_threshold) return {};   // small room → mesh

    const ForwarderCandidate* best = nullptr;
    for (const auto& c : candidates) {
        if (c.uplink_class <= 0) continue;               // not a usable relay
        if (!best ||
            c.uplink_class > best->uplink_class ||
            (c.uplink_class == best->uplink_class && c.pubkey < best->pubkey)) {
            best = &c;
        }
    }
    return best ? best->pubkey : std::string{};          // none capable → mesh
}

ForwarderPlan plan_topology(const std::vector<std::string>& participants,
                            const std::string& my_pubkey,
                            const std::string& forwarder) {
    ForwarderPlan plan;
    plan.forwarder = forwarder;

    if (forwarder.empty()) {
        // Full mesh: dial every other participant.
        plan.mesh = true;
        for (const auto& p : participants) {
            if (p != my_pubkey) plan.dial.push_back(p);
        }
    } else if (forwarder == my_pubkey) {
        // I'm the forwarder: connect to everyone else.
        plan.mesh = false;
        plan.i_am_forwarder = true;
        for (const auto& p : participants) {
            if (p != my_pubkey) plan.dial.push_back(p);
        }
    } else {
        // Leaf: only connect to the forwarder.
        plan.mesh = false;
        plan.dial.push_back(forwarder);
    }
    std::sort(plan.dial.begin(), plan.dial.end());
    return plan;
}

std::map<std::string, VideoQuality> plan_forwarded_video(
    const std::map<std::string, double>& levels,
    std::size_t max_high, std::size_t max_thumbnail, double floor_db) {
    std::map<std::string, VideoQuality> out;

    // Rank talkers (above floor) loudest-first; ties by key for determinism.
    std::vector<std::pair<double, std::string>> talking;
    for (const auto& [key, lvl] : levels) {
        if (lvl >= floor_db) talking.emplace_back(lvl, key);
    }
    std::sort(talking.begin(), talking.end(),
              [](const auto& a, const auto& b) {
                  if (a.first != b.first) return a.first > b.first;
                  return a.second < b.second;
              });

    // Top `max_high` talkers → HIGH.
    std::size_t hi = 0;
    for (; hi < talking.size() && hi < max_high; ++hi) {
        out[talking[hi].second] = VideoQuality::kHigh;
    }
    // Everyone else (talkers past the high tier, then silent peers in key
    // order) → THUMBNAIL up to the budget, then DROP. Deterministic.
    std::size_t thumbs = 0;
    auto give = [&](const std::string& key) {
        if (out.count(key)) return;                 // already HIGH
        if (thumbs < max_thumbnail) {
            out[key] = VideoQuality::kThumbnail;
            ++thumbs;
        } else {
            out[key] = VideoQuality::kDrop;
        }
    };
    for (std::size_t i = hi; i < talking.size(); ++i) give(talking[i].second);
    for (const auto& [key, _] : levels) give(key);  // silent peers (key order)
    return out;
}

std::vector<TreeNode> build_distribution_tree(
    const std::vector<ForwarderCandidate>& nodes, std::size_t fanout) {
    if (fanout < 1) fanout = 1;
    std::vector<TreeNode> out;
    if (nodes.empty()) return out;

    // Strongest first (uplink_class desc), ties by pubkey asc → deterministic.
    std::vector<ForwarderCandidate> ranked(nodes);
    std::sort(ranked.begin(), ranked.end(),
              [](const ForwarderCandidate& a, const ForwarderCandidate& b) {
                  if (a.uplink_class != b.uplink_class)
                      return a.uplink_class > b.uplink_class;
                  return a.pubkey < b.pubkey;
              });

    // Root, then breadth-first attach each remaining node to the earliest
    // parent with a free child slot — keeps the tree balanced/shallow.
    out.push_back({ranked[0].pubkey, /*parent=*/"", /*depth=*/0});
    std::size_t parent_idx = 0;       // index into `out` of the current parent
    std::size_t children_of_parent = 0;
    for (std::size_t i = 1; i < ranked.size(); ++i) {
        if (children_of_parent == fanout) {
            ++parent_idx;             // next parent in BFS order
            children_of_parent = 0;
        }
        out.push_back({ranked[i].pubkey, out[parent_idx].pubkey,
                       out[parent_idx].depth + 1});
        ++children_of_parent;
    }
    return out;
}

// ---------------------------------------------------------------------------
// ForwarderRouting
// ---------------------------------------------------------------------------
std::vector<ForwardEdge> ForwarderRouting::add_leaf(const std::string& leaf) {
    std::vector<ForwardEdge> added;
    if (leaf.empty() || leaves_.count(leaf)) return added;   // no-op
    // New leaf both sends to and receives from every existing leaf.
    for (const auto& other : leaves_) {
        added.push_back({leaf, other});   // leaf's stream → other
        added.push_back({other, leaf});   // other's stream → leaf
    }
    leaves_.insert(leaf);
    std::sort(added.begin(), added.end());
    return added;
}

std::vector<ForwardEdge> ForwarderRouting::remove_leaf(const std::string& leaf) {
    std::vector<ForwardEdge> removed;
    if (!leaves_.erase(leaf)) return removed;   // wasn't a leaf
    for (const auto& other : leaves_) {
        removed.push_back({leaf, other});   // leaf's stream → other (gone)
        removed.push_back({other, leaf});   // other's stream → leaf (gone)
    }
    std::sort(removed.begin(), removed.end());
    return removed;
}

std::vector<ForwardEdge> ForwarderRouting::edges() const {
    std::vector<ForwardEdge> all;
    for (const auto& a : leaves_)
        for (const auto& b : leaves_)
            if (a != b) all.push_back({a, b});
    std::sort(all.begin(), all.end());     // leaves_ is sorted; this is belt+braces
    return all;
}

std::vector<std::string> ForwarderRouting::subscribers_of(
    const std::string& src) const {
    std::vector<std::string> subs;
    if (!leaves_.count(src)) return subs;
    for (const auto& other : leaves_)
        if (other != src) subs.push_back(other);
    return subs;                            // already sorted (std::set order)
}

std::vector<std::string> ForwarderRouting::leaves() const {
    return std::vector<std::string>(leaves_.begin(), leaves_.end());
}

std::size_t ForwarderRouting::leaf_count() const { return leaves_.size(); }

bool ForwarderRouting::has_leaf(const std::string& leaf) const {
    return leaves_.count(leaf) != 0;
}

}  // namespace fb::media
