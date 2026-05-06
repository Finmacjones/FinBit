// SPDX-License-Identifier: AGPL-3.0-or-later
#include "message_delegate.hpp"

#include <QAbstractTextDocumentLayout>
#include <QDateTime>
#include <QPainter>
#include <QTextDocument>
#include <QTextOption>

#include "avatar.hpp"

namespace fb::desktop {

namespace {
constexpr int kAvatarSize    = 40;
constexpr int kAvatarMargin  = 16;
constexpr int kRowVMargin    = 4;
constexpr int kHeaderHeight  = 22;
constexpr int kBodyTopGap    = 2;
}

namespace {

QColor sender_color(const QString& seed, bool is_self) {
    if (is_self) return QColor("#00aff4");  // Discord-ish blue for self
    // Reuse the avatar's hue formula so name + avatar match.
    constexpr std::uint32_t kPrime = 16777619u;
    std::uint32_t h = 2166136261u;
    for (auto c : seed.toUtf8()) { h ^= static_cast<std::uint8_t>(c); h *= kPrime; }
    return QColor::fromHsv(static_cast<int>(h % 360u), 200, 230);
}

}  // namespace

void MessageDelegate::paint(QPainter* p, const QStyleOptionViewItem& opt,
                            const QModelIndex& idx) const {
    p->save();
    // Hover / selected backgrounds — Discord uses a subtle darker tint.
    if (opt.state & QStyle::State_Selected) {
        p->fillRect(opt.rect, QColor("#393c43"));
    } else if (opt.state & QStyle::State_MouseOver) {
        p->fillRect(opt.rect, QColor("#34373c"));
    }

    const QString sender = idx.data(RoleSenderName).toString();
    const QString seed   = idx.data(RoleSenderSeed).toString().isEmpty()
                               ? sender
                               : idx.data(RoleSenderSeed).toString();
    const QString body   = idx.data(RoleBody).toString();
    const qint64  ts     = idx.data(RoleTimestamp).toLongLong();
    const bool is_self   = idx.data(RoleIsSelf).toBool();
    const bool is_hist   = idx.data(RoleIsHistory).toBool();

    // Avatar.
    const QPixmap avatar = make_avatar(seed, kAvatarSize);
    p->drawPixmap(opt.rect.x() + kAvatarMargin, opt.rect.y() + kRowVMargin, avatar);

    const int text_x = opt.rect.x() + kAvatarMargin + kAvatarSize + 12;
    const int text_w = opt.rect.right() - text_x - 16;

    // Header line: "name  ts"
    QFont name_font = p->font();
    name_font.setBold(true);
    p->setFont(name_font);
    QColor name_col = sender_color(seed, is_self);
    if (is_hist) name_col.setAlpha(150);
    p->setPen(name_col);
    QFontMetrics fm_name(name_font);
    const QString name_display = sender;
    p->drawText(text_x, opt.rect.y() + kRowVMargin + fm_name.ascent(), name_display);
    const int name_w = fm_name.horizontalAdvance(name_display);

    QFont ts_font = p->font();
    ts_font.setBold(false);
    ts_font.setPixelSize(11);
    p->setFont(ts_font);
    p->setPen(QColor(is_hist ? "#5c6066" : "#72767d"));
    const QString ts_str =
        QDateTime::fromMSecsSinceEpoch(ts).toString("HH:mm");
    QFontMetrics fm_ts(ts_font);
    p->drawText(text_x + name_w + 8,
                opt.rect.y() + kRowVMargin + fm_name.ascent(),
                "Today at " + ts_str);

    // Body — let QTextDocument wrap it within the available width.
    QFont body_font = opt.font;
    p->setFont(body_font);
    QTextDocument doc;
    doc.setDefaultFont(body_font);
    doc.setTextWidth(text_w);
    doc.setPlainText(body);
    p->translate(text_x, opt.rect.y() + kRowVMargin + kHeaderHeight + kBodyTopGap);
    QAbstractTextDocumentLayout::PaintContext ctx;
    ctx.palette.setColor(QPalette::Text,
                         is_hist ? QColor("#888c92") : QColor("#dcddde"));
    doc.documentLayout()->draw(p, ctx);
    p->restore();
}

QSize MessageDelegate::sizeHint(const QStyleOptionViewItem& opt,
                                const QModelIndex& idx) const {
    const QString body = idx.data(RoleBody).toString();
    QTextDocument doc;
    QFont f = opt.font;
    doc.setDefaultFont(f);
    const int w = opt.widget ? opt.widget->width() - kAvatarMargin - kAvatarSize - 28 - 16
                              : 600;
    doc.setTextWidth(w);
    doc.setPlainText(body);
    const int body_h = static_cast<int>(doc.size().height()) + kBodyTopGap;
    const int h = kRowVMargin + kHeaderHeight + body_h + kRowVMargin;
    return QSize(opt.rect.width(), std::max(h, kAvatarSize + 2 * kRowVMargin));
}

}  // namespace fb::desktop
