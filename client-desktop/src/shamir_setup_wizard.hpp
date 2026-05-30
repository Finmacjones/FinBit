// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Tier-11 Shamir social-recovery setup wizard.
//
// Two-page modal that walks the user through:
//   1. Unlock the vault to recover the raw 32-byte identity seed
//      (the same passphrase they used at sign-in — Argon2id + XChaCha20
//      via identity_vault::open_seed). The seed lives in stack-allocated
//      memory inside this dialog and is sodium_memzero'd on destruction.
//   2. Pick N trusted contacts (multi-select from the desktop's known-DM
//      list) + a threshold M (any M of the N can later reconstruct).
//      Click [Distribute] → for each picked contact, ratchet-seal a
//      ShamirSharePush DM via ChatClient::sendShamirShareTo.
//
// The contacts' own desktops persist the shares to their sqlite store
// (shamir_held_shares) and surface a "now holding a share for you" UI
// notification (shamirShareReceived signal — handled elsewhere in
// main_window).
//
// Recovery (the symmetric flow — ask M trustees to send the shares back,
// recombine, restore the vault) is a SEPARATE wizard. This dialog is
// the setup half only.

#include <QDialog>
#include <QString>
#include <QStringList>

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QSpinBox;
class QStackedWidget;

namespace fb::desktop {

class ChatClient;

class ShamirSetupWizard : public QDialog {
    Q_OBJECT
public:
    // `username` identifies the local vault file to unlock for the seed.
    // `candidate_contacts` populates the trustee picker — typically the
    // current dm_list usernames.
    ShamirSetupWizard(ChatClient*        client,
                       const QString&     username,
                       const QStringList& candidate_contacts,
                       QWidget*           parent = nullptr);
    ~ShamirSetupWizard() override;

private slots:
    void onUnlockClicked();
    void onDistributeClicked();
    void onSelectionChanged();

private:
    void show_error(const QString& msg);

    ChatClient*  client_;
    QString      username_;

    QStackedWidget* pages_           = nullptr;
    QLabel*         error_label_     = nullptr;

    // Page 1 — vault unlock.
    QLineEdit*   passphrase_input_  = nullptr;
    QPushButton* unlock_btn_        = nullptr;

    // Page 2 — pick contacts + threshold.
    QListWidget* contacts_list_     = nullptr;
    QSpinBox*    threshold_spin_    = nullptr;
    QLabel*      threshold_summary_ = nullptr;
    QLineEdit*   label_input_       = nullptr;
    QPushButton* distribute_btn_    = nullptr;

    // Seed lives only on the heap between page 1 and page 2 ack; cleared
    // on destruction. std::array (not std::vector) so destructor zeroizes
    // before deallocation rather than after.
    std::array<std::uint8_t, 32> seed_{};
    bool seed_loaded_ = false;
};

}  // namespace fb::desktop
