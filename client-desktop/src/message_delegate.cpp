// SPDX-License-Identifier: AGPL-3.0-or-later
#include "message_delegate.hpp"

#include <QAbstractTextDocumentLayout>
#include <QBuffer>
#include <QDateTime>
#include <QImage>
#include <QImageReader>
#include <QMovie>
#include <QPainter>
#include <QPixmap>
#include <QTextDocument>
#include <QTextOption>
#include <QWidget>

#include <algorithm>

#include "avatar.hpp"

namespace fb::desktop {

namespace {
constexpr int kAvatarSize    = 40;
constexpr int kAvatarMargin  = 16;
constexpr int kRowVMargin    = 4;
constexpr int kHeaderHeight  = 22;
constexpr int kBodyTopGap    = 2;
constexpr int kImageMaxW     = 360;   // inline image display box
constexpr int kImageMaxH     = 360;

// Natural pixel size of an encoded image, read cheaply (header only)
// without decoding the whole frame. Falls back to a square if unknown.
QSize natural_image_size(const QByteArray& bytes) {
    QBuffer buf;
    buf.setData(bytes);
    buf.open(QIODevice::ReadOnly);
    QImageReader r(&buf);
    const QSize s = r.size();
    return s.isValid() ? s : QSize(200, 200);
}

// Box `nat` into max_w × max_h, preserving aspect ratio; never upscale.
QSize fit_within(QSize nat, int max_w, int max_h) {
    if (nat.width() <= max_w && nat.height() <= max_h) return nat;
    return nat.scaled(max_w, max_h, Qt::KeepAspectRatio);
}
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

MessageDelegate::~MessageDelegate() {
    qDeleteAll(movies_);   // each QMovie owns its QBuffer (set as parent)
}

QMovie* MessageDelegate::movie_for(const QByteArray& bytes, QWidget* view) const {
    auto it = movies_.find(bytes);
    if (it != movies_.end()) return it.value();
    auto* buf = new QBuffer();
    buf->setData(bytes);
    buf->open(QIODevice::ReadOnly);
    auto* mv = new QMovie(buf);
    buf->setParent(mv);                 // freed together with the movie
    mv->setCacheMode(QMovie::CacheAll);
    if (view) {
        // Repaint the list as each GIF frame advances so it animates in
        // place. `view` as the connection context auto-disconnects if the
        // view goes away.
        QObject::connect(mv, &QMovie::frameChanged, view,
                         [view]() { view->update(); });
    }
    mv->start();
    movies_.insert(bytes, mv);
    return mv;
}

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

    // Body — an inline image/GIF if present, otherwise wrapped text.
    const QByteArray img = idx.data(RoleImageBytes).toByteArray();
    const int body_y = opt.rect.y() + kRowVMargin + kHeaderHeight + kBodyTopGap;
    if (!img.isEmpty()) {
        const QString mime = idx.data(RoleImageMime).toString();
        QPixmap pm;
        if (mime == QLatin1String("image/gif")) {
            if (QMovie* mv = movie_for(img, const_cast<QWidget*>(opt.widget))) {
                pm = mv->currentPixmap();
            }
        }
        if (pm.isNull()) {
            pm = QPixmap::fromImage(QImage::fromData(img));
        }
        if (!pm.isNull()) {
            const QSize box = fit_within(pm.size(),
                                         std::min(text_w, kImageMaxW), kImageMaxH);
            const QPixmap scaled = pm.scaled(box, Qt::KeepAspectRatio,
                                             Qt::SmoothTransformation);
            p->drawPixmap(text_x, body_y, scaled);
        } else {
            // Undecodable bytes — show a placeholder rather than nothing.
            p->setPen(QColor("#ed4245"));
            p->drawText(text_x, body_y + 14, QStringLiteral("[unsupported image]"));
        }
        p->restore();
        return;
    }

    QFont body_font = opt.font;
    p->setFont(body_font);
    QTextDocument doc;
    doc.setDefaultFont(body_font);
    doc.setTextWidth(text_w);
    doc.setPlainText(body);
    p->translate(text_x, body_y);
    QAbstractTextDocumentLayout::PaintContext ctx;
    ctx.palette.setColor(QPalette::Text,
                         is_hist ? QColor("#888c92") : QColor("#dcddde"));
    doc.documentLayout()->draw(p, ctx);
    p->restore();
}

QSize MessageDelegate::sizeHint(const QStyleOptionViewItem& opt,
                                const QModelIndex& idx) const {
    const int avail_w = opt.widget
        ? opt.widget->width() - kAvatarMargin - kAvatarSize - 28 - 16 : 600;

    // Image rows: height = header + boxed image.
    const QByteArray img = idx.data(RoleImageBytes).toByteArray();
    if (!img.isEmpty()) {
        const QSize box = fit_within(natural_image_size(img),
                                     std::min(avail_w, kImageMaxW), kImageMaxH);
        const int h = kRowVMargin + kHeaderHeight + kBodyTopGap +
                      box.height() + kRowVMargin;
        return QSize(opt.rect.width(),
                     std::max(h, kAvatarSize + 2 * kRowVMargin));
    }

    const QString body = idx.data(RoleBody).toString();
    QTextDocument doc;
    QFont f = opt.font;
    doc.setDefaultFont(f);
    doc.setTextWidth(avail_w);
    doc.setPlainText(body);
    const int body_h = static_cast<int>(doc.size().height()) + kBodyTopGap;
    const int h = kRowVMargin + kHeaderHeight + body_h + kRowVMargin;
    return QSize(opt.rect.width(), std::max(h, kAvatarSize + 2 * kRowVMargin));
}

}  // namespace fb::desktop
