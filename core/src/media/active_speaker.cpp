// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/active_speaker.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace fb::media {

std::set<std::string> select_active_speakers(
    const std::map<std::string, double>& levels,
    std::size_t max_active, double floor_db) {
    std::set<std::string> audible;

    // Who is actually talking (at/above the floor)?
    std::vector<std::pair<double, std::string>> talking;  // (level, key)
    for (const auto& [key, lvl] : levels) {
        if (lvl >= floor_db) talking.emplace_back(lvl, key);
    }

    // Not over capacity → gate nobody (every peer stays audible; silent
    // peers send ~nothing anyway thanks to DTX). This also covers the
    // common case and avoids clipping a peer who's about to speak.
    if (talking.size() <= max_active) {
        for (const auto& [key, _] : levels) audible.insert(key);
        return audible;
    }

    // Over capacity → keep the loudest `max_active` talkers audible, gate
    // the rest. partial_sort puts the top `max_active` (by level desc) at
    // the front. Ties broken by key for determinism.
    std::partial_sort(
        talking.begin(),
        talking.begin() + static_cast<std::ptrdiff_t>(max_active),
        talking.end(),
        [](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first > b.first;
            return a.second < b.second;
        });
    for (std::size_t i = 0; i < max_active; ++i) {
        audible.insert(talking[i].second);
    }
    return audible;
}

}  // namespace fb::media
