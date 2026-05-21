// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Active-speaker selection for many-party mesh calls (Lever A of the no-SFU
// scaling plan, docs/serverless-group-calls.md).
//
// Each participant meters every inbound peer's audio RMS (dBFS, ≤0). When
// more than `max_active` peers are talking AT ONCE, we keep only the
// loudest `max_active` audible and gate (mute playback of) the rest — a
// cacophony cap + CPU/UX safety valve. When `max_active` or fewer are
// talking, NOBODY is gated (so a quiet peer who speaks is heard with no
// clipping). Pure + deterministic so it's unit-tested without GStreamer.
// =============================================================================

#include <cstddef>
#include <map>
#include <set>
#include <string>

namespace fb::media {

// `levels`: peer-key → most-recent inbound RMS in dBFS (≤0; ~-120 on
// silence). `max_active`: how many simultaneous talkers to keep audible.
// `floor_db`: at/above this is "talking" (e.g. -50 dBFS).
//
// Returns the set of peer keys that should remain AUDIBLE. Callers gate
// (mute) every peer NOT in the returned set.
[[nodiscard]] std::set<std::string> select_active_speakers(
    const std::map<std::string, double>& levels,
    std::size_t max_active, double floor_db);

}  // namespace fb::media
