// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Discord-style message delegate. Each row paints:
//   - 40px circular avatar on the left (color + monogram from sender seed)
//   - sender name (colored) + small grey timestamp on the first line
//   - body text below, word-wrapped to the row width
//
// Item data layout (Qt::UserRole offsets):
//   +0 : QString  sender display name (or fingerprint)
//   +1 : QString  sender seed for the avatar (usually fingerprint)
//   +2 : QString  body text
//   +3 : qint64   timestamp_ms
//   +4 : bool     is_self
//   +5 : bool     is_history (greyed)

#include <QStyledItemDelegate>

namespace fb::desktop {

class MessageDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    static constexpr int RoleSenderName = Qt::UserRole + 0;
    static constexpr int RoleSenderSeed = Qt::UserRole + 1;
    static constexpr int RoleBody       = Qt::UserRole + 2;
    static constexpr int RoleTimestamp  = Qt::UserRole + 3;
    static constexpr int RoleIsSelf     = Qt::UserRole + 4;
    static constexpr int RoleIsHistory  = Qt::UserRole + 5;

    void paint(QPainter* p, const QStyleOptionViewItem& opt,
               const QModelIndex& idx) const override;
    QSize sizeHint(const QStyleOptionViewItem& opt,
                   const QModelIndex& idx) const override;
};

}  // namespace fb::desktop
