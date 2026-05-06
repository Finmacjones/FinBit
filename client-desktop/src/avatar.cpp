// SPDX-License-Identifier: AGPL-3.0-or-later
#include "avatar.hpp"

#include <QColor>
#include <QFont>
#include <QPainter>
#include <QPainterPath>

namespace fb::desktop {

namespace {

// FNV-1a 32-bit hash — small + dependency-free, plenty for picking a hue.
std::uint32_t fnv1a(const QString& s) {
    constexpr std::uint32_t kPrime = 16777619u;
    std::uint32_t h = 2166136261u;
    const QByteArray b = s.toUtf8();
    for (auto c : b) {
        h ^= static_cast<std::uint8_t>(c);
        h *= kPrime;
    }
    return h;
}

QString monogram(const QString& s) {
    // Skip leading non-alphanumerics; take up to 2 chars (filtered).
    QString out;
    for (auto c : s) {
        if (c.isLetterOrNumber()) {
            out.append(c.toUpper());
            if (out.size() == 2) break;
        }
    }
    if (out.isEmpty()) out = "?";
    return out;
}

}  // namespace

QPixmap make_avatar(const QString& seed_text, int size) {
    const std::uint32_t h = fnv1a(seed_text);
    // Discord-ish saturation/value with a hue spread across 360°.
    QColor bg = QColor::fromHsv(static_cast<int>(h % 360u), 180, 200);

    QPixmap pm(size, size);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setBrush(bg);
    p.setPen(Qt::NoPen);
    p.drawEllipse(0, 0, size, size);

    QFont f = p.font();
    f.setBold(true);
    f.setPixelSize(size * 4 / 10);
    p.setFont(f);
    p.setPen(QColor("#ffffff"));
    p.drawText(QRect(0, 0, size, size), Qt::AlignCenter, monogram(seed_text));
    return pm;
}

}  // namespace fb::desktop
