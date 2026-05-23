// SPDX-License-Identifier: AGPL-3.0-or-later
#include "crt_overlay.hpp"

#include <QPainter>
#include <QPaintEvent>
#include <QRadialGradient>
#include <QRandomGenerator>
#include <QTimer>

namespace fb::desktop {

CrtOverlay::CrtOverlay(QWidget* parent) : QWidget(parent) {
    // Click-through, no background of its own, never steals focus.
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setAttribute(Qt::WA_NoSystemBackground);
    setAttribute(Qt::WA_TranslucentBackground);
    setFocusPolicy(Qt::NoFocus);

    // One faint phosphor scanline per 3px, built once and tiled at paint time.
    scan_tile_ = QPixmap(1, 3);
    scan_tile_.fill(Qt::transparent);
    {
        QPainter tp(&scan_tile_);
        tp.fillRect(0, 0, 1, 1, QColor(0, 255, 157, 28));
    }

    timer_ = new QTimer(this);
    timer_->setInterval(90);  // ~11 Hz flicker tick
    connect(timer_, &QTimer::timeout, this, [this]() {
        const int r = QRandomGenerator::global()->bounded(100);
        flicker_ = (r < 5) ? 0.90 : (r < 11 ? 0.97 : 1.0);
        update();
    });
    timer_->start();
}

void CrtOverlay::setEffectsEnabled(bool on) {
    enabled_ = on;
    setVisible(on);
    if (on) {
        timer_->start();
        raise();
    } else {
        timer_->stop();
    }
    update();
}

void CrtOverlay::paintEvent(QPaintEvent*) {
    if (!enabled_) return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, false);

    // Scanlines (cheap: tiled pixmap), brightness modulated by the flicker.
    p.setOpacity(flicker_);
    p.drawTiledPixmap(rect(), scan_tile_);
    p.setOpacity(1.0);

    // On a flicker dip, darken the whole surface slightly.
    if (flicker_ < 1.0) {
        p.fillRect(rect(), QColor(0, 0, 0, int((1.0 - flicker_) * 90)));
    }

    // Phosphor-tube vignette.
    QRadialGradient g(width() / 2.0, height() / 2.0, qMax(width(), height()) * 0.75);
    g.setColorAt(0.55, QColor(0, 0, 0, 0));
    g.setColorAt(1.0, QColor(0, 0, 0, 120));
    p.fillRect(rect(), g);
}

}  // namespace fb::desktop
