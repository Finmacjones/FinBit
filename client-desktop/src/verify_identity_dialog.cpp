// SPDX-License-Identifier: AGPL-3.0-or-later
#include "verify_identity_dialog.hpp"

#include "chat_client.hpp"

#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace fb::desktop {

VerifyIdentityDialog::VerifyIdentityDialog(ChatClient* client,
                                            const QString& peerLabel,
                                            const QByteArray& peerPubkey,
                                            QWidget* parent)
    : QDialog(parent),
      client_(client),
      peer_pubkey_(peerPubkey),
      peer_label_(peerLabel) {
    setWindowTitle(tr("Verify identity"));
    setModal(true);

    auto* root = new QVBoxLayout(this);

    auto* intro = new QLabel(
        tr("Compare the safety number with %1 over a channel you "
           "trust (in person, voice call, signed message). If the "
           "numbers match, no man-in-the-middle has substituted "
           "either of your pubkeys. If they DON'T match — stop using "
           "this conversation until you verify why.").arg(peer_label_));
    intro->setWordWrap(true);
    root->addWidget(intro);

    my_fp_label_   = new QLabel(this);
    peer_fp_label_ = new QLabel(this);
    root->addWidget(my_fp_label_);
    root->addWidget(peer_fp_label_);

    auto* sep = new QLabel(tr("\nSafety number — read aloud:"));
    sep->setStyleSheet("font-weight: bold; margin-top: 8px;");
    root->addWidget(sep);

    safety_number_lbl_ = new QLabel(this);
    // Monospace so the 12-group layout reads cleanly.
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSize(mono.pointSize() + 2);
    safety_number_lbl_->setFont(mono);
    safety_number_lbl_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    safety_number_lbl_->setWordWrap(true);
    root->addWidget(safety_number_lbl_);

    verified_status_ = new QLabel(this);
    verified_status_->setStyleSheet("margin-top: 12px;");
    root->addWidget(verified_status_);

    auto* btn_row = new QHBoxLayout;
    verify_btn_ = new QPushButton(this);
    btn_row->addWidget(verify_btn_);
    btn_row->addStretch();
    auto* close = new QPushButton(tr("Close"), this);
    btn_row->addWidget(close);
    root->addLayout(btn_row);

    connect(verify_btn_, &QPushButton::clicked,
            this, &VerifyIdentityDialog::toggleVerified);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);

    refresh();
}

VerifyIdentityDialog::~VerifyIdentityDialog() = default;

void VerifyIdentityDialog::toggleVerified() {
    if (!client_) return;
    const bool now_verified = !client_->isPeerVerified(peer_pubkey_);
    client_->setPeerVerified(peer_pubkey_, now_verified);
    refresh();
}

void VerifyIdentityDialog::refresh() {
    if (!client_) return;

    const auto sn = client_->safetyNumberFor(peer_pubkey_);
    safety_number_lbl_->setText(sn.isEmpty() ? tr("(no peer pubkey)") : sn);

    my_fp_label_->setText(tr("Your fingerprint:   %1")
                              .arg(client_->myFingerprint()));
    peer_fp_label_->setText(tr("Peer fingerprint:   %1")
                                 .arg(peer_label_));

    const bool verified = client_->isPeerVerified(peer_pubkey_);
    if (verified) {
        verified_status_->setText(tr("✓ Marked verified."));
        verified_status_->setStyleSheet(
            "color: #2e7d32; font-weight: bold; margin-top: 12px;");
        verify_btn_->setText(tr("Unmark as verified"));
    } else {
        verified_status_->setText(
            tr("⚠ NOT yet verified. Compare the number, then click below."));
        verified_status_->setStyleSheet(
            "color: #c62828; margin-top: 12px;");
        verify_btn_->setText(tr("Mark verified"));
    }
}

}  // namespace fb::desktop
