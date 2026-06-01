// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shamir_setup_wizard.hpp"

#include "chat_client.hpp"
#include "identity_vault.hpp"

#include "fb/crypto/shamir.hpp"

#include <sodium.h>

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QRandomGenerator>
#include <QSpinBox>
#include <QStackedWidget>
#include <QVBoxLayout>

namespace fb::desktop {

namespace {
constexpr int kPageUnlock     = 0;
constexpr int kPageDistribute = 1;
}  // namespace

ShamirSetupWizard::ShamirSetupWizard(ChatClient* client,
                                      const QString& username,
                                      const QStringList& candidate_contacts,
                                      QWidget* parent)
    : QDialog(parent), client_(client), username_(username) {
    setWindowTitle(tr("Social recovery — setup"));
    setModal(true);
    resize(540, 420);

    auto* root = new QVBoxLayout(this);
    pages_ = new QStackedWidget(this);
    root->addWidget(pages_);

    // ---- Page 1: unlock vault to get the seed ----
    {
        auto* page = new QWidget(this);
        auto* l = new QVBoxLayout(page);
        auto* hd = new QLabel(tr(
            "<b>Step 1 of 2 — Unlock your vault.</b>\n\n"
            "Social recovery splits your identity seed into N shares so "
            "that any M of them can reconstruct it. To split the seed we "
            "need to read it from your vault — enter the passphrase you "
            "use to sign in."));
        hd->setWordWrap(true);
        hd->setTextFormat(Qt::RichText);
        l->addWidget(hd);

        passphrase_input_ = new QLineEdit(page);
        passphrase_input_->setEchoMode(QLineEdit::Password);
        passphrase_input_->setPlaceholderText(tr("vault passphrase"));
        l->addWidget(passphrase_input_);

        l->addStretch();
        auto* row = new QHBoxLayout;
        row->addStretch();
        unlock_btn_ = new QPushButton(tr("Unlock"), page);
        unlock_btn_->setDefault(true);
        row->addWidget(unlock_btn_);
        auto* cancel = new QPushButton(tr("Cancel"), page);
        row->addWidget(cancel);
        l->addLayout(row);

        connect(unlock_btn_, &QPushButton::clicked,
                this, &ShamirSetupWizard::onUnlockClicked);
        connect(passphrase_input_, &QLineEdit::returnPressed,
                this, &ShamirSetupWizard::onUnlockClicked);
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        pages_->addWidget(page);
    }

    // ---- Page 2: pick contacts + threshold, distribute ----
    {
        auto* page = new QWidget(this);
        auto* l = new QVBoxLayout(page);
        auto* hd = new QLabel(tr(
            "<b>Step 2 of 2 — Distribute shares.</b>\n\n"
            "Pick the contacts you trust to hold a share of your seed. "
            "Each share alone reveals nothing; any <b>M</b> shares "
            "reconstruct the seed. Recommended: at least M=3 of N=5 "
            "trusted people from different social circles, so no single "
            "incident (lost phone, coerced contact) compromises recovery."));
        hd->setWordWrap(true);
        hd->setTextFormat(Qt::RichText);
        l->addWidget(hd);

        contacts_list_ = new QListWidget(page);
        contacts_list_->setSelectionMode(QAbstractItemView::MultiSelection);
        for (const auto& name : candidate_contacts) {
            contacts_list_->addItem(name);
        }
        l->addWidget(contacts_list_, /*stretch=*/1);

        auto* threshold_row = new QHBoxLayout;
        threshold_row->addWidget(new QLabel(tr("Threshold M:")));
        threshold_spin_ = new QSpinBox(page);
        threshold_spin_->setRange(1, 255);
        threshold_spin_->setValue(3);
        threshold_row->addWidget(threshold_spin_);
        threshold_summary_ = new QLabel(this);
        threshold_summary_->setStyleSheet("color: #555;");
        threshold_row->addWidget(threshold_summary_, /*stretch=*/1);
        l->addLayout(threshold_row);

        auto* label_row = new QHBoxLayout;
        label_row->addWidget(new QLabel(tr("Label (optional):")));
        label_input_ = new QLineEdit(page);
        label_input_->setPlaceholderText(tr("e.g. \"primary seed\" — shown to trustees"));
        label_row->addWidget(label_input_);
        l->addLayout(label_row);

        error_label_ = new QLabel(this);
        error_label_->setStyleSheet("color: #c62828;");
        error_label_->setWordWrap(true);
        l->addWidget(error_label_);

        auto* row = new QHBoxLayout;
        row->addStretch();
        distribute_btn_ = new QPushButton(tr("Distribute"), page);
        distribute_btn_->setEnabled(false);
        row->addWidget(distribute_btn_);
        auto* cancel = new QPushButton(tr("Cancel"), page);
        row->addWidget(cancel);
        l->addLayout(row);

        connect(contacts_list_, &QListWidget::itemSelectionChanged,
                this, &ShamirSetupWizard::onSelectionChanged);
        connect(threshold_spin_,
                QOverload<int>::of(&QSpinBox::valueChanged),
                this, &ShamirSetupWizard::onSelectionChanged);
        connect(distribute_btn_, &QPushButton::clicked,
                this, &ShamirSetupWizard::onDistributeClicked);
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        pages_->addWidget(page);
    }

    pages_->setCurrentIndex(kPageUnlock);
}

ShamirSetupWizard::~ShamirSetupWizard() {
    // Defensively zero the seed bytes even if the dialog was rejected
    // mid-flow. std::array<u8, 32> bytes are in-line storage, so this
    // touches the actual backing memory rather than a moved-from heap
    // allocation.
    sodium_memzero(seed_.data(), seed_.size());
}

void ShamirSetupWizard::show_error(const QString& msg) {
    if (error_label_) error_label_->setText(msg);
}

void ShamirSetupWizard::onUnlockClicked() {
    const QString passphrase = passphrase_input_->text();
    if (passphrase.isEmpty()) {
        QMessageBox::warning(this, tr("Unlock"),
            tr("Enter your vault passphrase."));
        return;
    }
    const auto vault_path = fb::desktop::vault_path_for(username_);
    auto blob = fb::desktop::load_vault_file(vault_path);
    if (!blob) {
        QMessageBox::critical(this, tr("Unlock"),
            tr("No vault file found at %1.").arg(vault_path));
        return;
    }
    auto opened = fb::desktop::open_seed_multi(passphrase, *blob);
    if (!opened) {
        QMessageBox::critical(this, tr("Unlock"),
            tr("Wrong passphrase, or vault corrupt."));
        passphrase_input_->clear();
        return;
    }
    seed_ = *opened;
    seed_loaded_ = true;
    // F6 (audit): wipe the seed bytes out of the `opened` optional now that
    // they've been copied into seed_ (which the destructor zeroizes). The
    // optional's payload is an in-line std::array, so this touches the real
    // backing store, not a moved-from heap allocation.
    sodium_memzero(opened->data(), opened->size());
    passphrase_input_->clear();   // don't leave the bytes on the widget
    pages_->setCurrentIndex(kPageDistribute);
    onSelectionChanged();   // refresh threshold summary
}

void ShamirSetupWizard::onSelectionChanged() {
    if (!contacts_list_ || !threshold_spin_ || !threshold_summary_) return;
    const int n = static_cast<int>(contacts_list_->selectedItems().size());
    const int m = threshold_spin_->value();
    threshold_summary_->setText(tr("%1-of-%2 selected").arg(m).arg(n));
    distribute_btn_->setEnabled(n >= 1 && m >= 1 && m <= n);
}

void ShamirSetupWizard::onDistributeClicked() {
    if (!seed_loaded_) {
        show_error(tr("Vault not unlocked. Restart the wizard."));
        return;
    }
    const auto picked = contacts_list_->selectedItems();
    const int total = static_cast<int>(picked.size());
    const int threshold = threshold_spin_->value();
    if (threshold > total || threshold < 1) {
        show_error(tr("Threshold must be 1..N (currently %1 of %2).")
                       .arg(threshold).arg(total));
        return;
    }

    std::vector<fb::crypto::shamir::Share> shares;
    try {
        shares = fb::crypto::shamir::split(
            std::span<const std::uint8_t>(seed_.data(), seed_.size()),
            static_cast<std::uint8_t>(threshold),
            static_cast<std::uint8_t>(total));
    } catch (const std::exception& e) {
        show_error(tr("Split failed: %1").arg(e.what()));
        return;
    }

    // Use a single setup_id for this entire distribution. 64 random bits
    // give each setup a unique tag in trustees' shamir_held_shares
    // composite key — supports re-runs without colliding with prior
    // setups they're already holding for us.
    std::uint64_t setup_id = 0;
    randombytes_buf(&setup_id, sizeof(setup_id));

    const QString label = label_input_->text();
    int sent = 0;
    for (int i = 0; i < picked.size(); ++i) {
        auto wire = fb::crypto::shamir::encode_share(shares[static_cast<std::size_t>(i)]);
        QByteArray share_qb(reinterpret_cast<const char*>(wire.data()),
                             static_cast<int>(wire.size()));
        client_->sendShamirShareTo(picked[i]->text(), share_qb, setup_id,
                                    static_cast<quint32>(threshold),
                                    static_cast<quint32>(total),
                                    label);
        // F6 (audit): each share is seed-derived secret material. Wipe the
        // local copies now that sendShamirShareTo has queued its own copy
        // (which the ratchet seals under the peer's session). QByteArray
        // doesn't zeroize on free, so do it explicitly.
        sodium_memzero(share_qb.data(), static_cast<std::size_t>(share_qb.size()));
        sodium_memzero(wire.data(), wire.size());
        ++sent;
    }

    // F6 (audit): wipe the in-memory Share polynomial evaluations too —
    // each share's y-bytes are derived from the secret.
    for (auto& sh : shares) {
        sodium_memzero(sh.y.data(), sh.y.size());
    }

    // Wipe the seed from our memory as soon as we've handed off the
    // shares to the ChatClient's outbound queue (the queued bytes are
    // ratchet-encrypted under each peer's session by the worker).
    sodium_memzero(seed_.data(), seed_.size());
    seed_loaded_ = false;

    QMessageBox::information(this, tr("Distributed"),
        tr("Queued %1 share(s) for delivery, threshold %2-of-%3 "
           "(setup id 0x%4).\n\n"
           "RECORD this setup ID somewhere safe — you'll need it to "
           "ask trustees for their shares later. Recovery without it "
           "still works, but trustees would have to manually pick "
           "from multiple held shares if they're holding shares for "
           "more than one of your setups.")
            .arg(sent).arg(threshold).arg(total)
            .arg(QString::number(setup_id, 16)));
    accept();
}

}  // namespace fb::desktop
