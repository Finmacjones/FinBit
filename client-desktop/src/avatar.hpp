// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Deterministic-from-fingerprint avatar circles. Same input → same color +
// monogram. Used for sidebar entries AND in-message avatars.

#include <QPixmap>
#include <QString>

namespace fb::desktop {

// Render a `size`px circular avatar for a fingerprint or username. Hue is
// derived from a hash of the input so the same identity always paints the
// same color across panes and runs. Inside the circle, two characters from
// the input are drawn in white as a monogram.
[[nodiscard]] QPixmap make_avatar(const QString& seed_text, int size);

}  // namespace fb::desktop
