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

}  // namespace fb::media
