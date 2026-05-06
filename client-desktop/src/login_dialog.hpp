// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Pre-MainWindow modal that gates the chat UI behind a passphrase-protected
// identity vault. Three panes (Create / Sign in / Recover) selected based on
// whether any vault files exist on disk; the user can switch between them.
//
// On accept the dialog exposes:
//   selected_username() -> QString
//   selected_seed()     -> 32-byte Ed25519 seed (zeroed on dialog destroy)
//
// Reject means the user closed the window — caller should quit the app.

#include <QDialog>
#include <QString>

#include <array>
#include <cstdint>
#include <memory>

#include "identity_vault.hpp"

class QLineEdit;
class QStackedWidget;
class QComboBox;
class QPushButton;
class QLabel;
class QPlainTextEdit;

namespace fb::desktop {

class LoginDialog : public QDialog {
    Q_OBJECT
public:
    explicit LoginDialog(QWidget* parent = nullptr);
    ~LoginDialog() override;

    // Valid only after exec() == QDialog::Accepted.
    QString selected_username() const { return username_; }
    Seed    selected_seed()     const { return seed_; }

private slots:
    void onCreatePane();
    void onSignInPane();
    void onRecoverPane();
    void onCreateAccept();
    void onSignInAccept();
    void onRecoverAccept();

private:
    void show_pane(int idx);
    void show_error(const QString& msg);

    QStackedWidget*  panes_       = nullptr;
    QLabel*          subtitle_    = nullptr;
    QLabel*          error_label_ = nullptr;

    // Create pane.
    QLineEdit*       create_user_  = nullptr;
    QLineEdit*       create_pass1_ = nullptr;
    QLineEdit*       create_pass2_ = nullptr;
    QPushButton*     create_btn_   = nullptr;

    // Sign-in pane.
    QComboBox*       signin_user_  = nullptr;
    QLineEdit*       signin_pass_  = nullptr;
    QPushButton*     signin_btn_   = nullptr;

    // Recover pane.
    QLineEdit*       recover_user_ = nullptr;
    QPlainTextEdit*  recover_hex_  = nullptr;
    QLineEdit*       recover_pass_ = nullptr;
    QPushButton*     recover_btn_  = nullptr;

    QString username_;
    Seed    seed_{};
};

}  // namespace fb::desktop
