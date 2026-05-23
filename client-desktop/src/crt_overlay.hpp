// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// CrtOverlay — the desktop client's animated CRT layer (Lever: phosphor theme).
// Qt QSS can't do scanlines / flicker / glow, so this is a frameless,
// click-through child widget painted over the whole window: faint phosphor
// scanlines, a vignette, and a subtle brightness flicker on a timer. Toggle it
// with setEffectsEnabled (wired to the View ▸ CRT effects menu + QSettings).

#include <QPixmap>
#include <QWidget>

class QTimer;

namespace fb::desktop {

class CrtOverlay : public QWidget {
    Q_OBJECT
public:
    explicit CrtOverlay(QWidget* parent);

    void setEffectsEnabled(bool on);
    [[nodiscard]] bool effectsEnabled() const { return enabled_; }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    bool     enabled_ = true;
    qreal    flicker_ = 1.0;       // 1.0 = full brightness; dips on flicker
    QPixmap  scan_tile_;           // 1×3 px phosphor scanline, tiled
    QTimer*  timer_ = nullptr;
};

}  // namespace fb::desktop
