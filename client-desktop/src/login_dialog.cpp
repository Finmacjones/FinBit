// SPDX-License-Identifier: AGPL-3.0-or-later
#include "login_dialog.hpp"

#include <sodium.h>
#include <QApplication>
#include <QComboBox>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QtConcurrent>

#include "fb/crypto/identity.hpp"
#include "bip39.hpp"

namespace fb::desktop {

namespace {
constexpr int kPaneCreate  = 0;
constexpr int kPaneSignIn  = 1;
constexpr int kPaneRecover = 2;
}  // namespace

LoginDialog::LoginDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("FinBit · Sign in");
    setModal(true);
    setMinimumWidth(420);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(28, 28, 28, 24);
    root->setSpacing(14);

    auto* title = new QLabel("FinBit", this);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet("font-size:24px; font-weight:600;");
    root->addWidget(title);

    subtitle_ = new QLabel(this);
    subtitle_->setAlignment(Qt::AlignCenter);
    subtitle_->setStyleSheet("color:#8e9297; font-size:12px;");
    root->addWidget(subtitle_);

    panes_ = new QStackedWidget(this);
    root->addWidget(panes_);

    error_label_ = new QLabel(this);
    error_label_->setStyleSheet("color:#ed4245; font-size:12px;");
    error_label_->setWordWrap(true);
    error_label_->hide();
    root->addWidget(error_label_);

    // ---- Create pane ----------------------------------------------------
    {
        auto* w = new QWidget(this);
        auto* form = new QFormLayout(w);
        create_user_  = new QLineEdit(w);
        create_pass1_ = new QLineEdit(w);
        create_pass2_ = new QLineEdit(w);
        create_user_->setPlaceholderText("alice");
        create_user_->setValidator(new QRegularExpressionValidator(
            QRegularExpression("[A-Za-z0-9._-]{1,32}"), w));
        create_pass1_->setEchoMode(QLineEdit::Password);
        create_pass2_->setEchoMode(QLineEdit::Password);
        create_pass1_->setPlaceholderText("long, memorable, unique");
        create_pass2_->setPlaceholderText("repeat");
        form->addRow("Username", create_user_);
        form->addRow("Passphrase", create_pass1_);
        form->addRow("Confirm", create_pass2_);
        auto* hint = new QLabel(
            "Your identity is generated locally. The seed is encrypted with "
            "Argon2id + XChaCha20-Poly1305 before it touches disk.", w);
        hint->setStyleSheet("color:#8e9297; font-size:11px;");
        hint->setWordWrap(true);
        form->addRow(hint);
        create_btn_ = new QPushButton("Create identity", w);
        create_btn_->setDefault(true);
        connect(create_btn_, &QPushButton::clicked, this, &LoginDialog::onCreateAccept);
        form->addRow("", create_btn_);

        auto* links = new QHBoxLayout;
        auto* toRecover = new QPushButton("I have a recovery code", w);
        toRecover->setObjectName("linkBtn");
        toRecover->setFlat(true);
        connect(toRecover, &QPushButton::clicked, this, &LoginDialog::onRecoverPane);
        links->addStretch();
        links->addWidget(toRecover);
        links->addStretch();
        form->addRow(links);
        panes_->addWidget(w);
    }

    // ---- Sign-in pane ---------------------------------------------------
    {
        auto* w = new QWidget(this);
        auto* form = new QFormLayout(w);
        signin_user_ = new QComboBox(w);
        signin_user_->setEditable(false);
        signin_pass_ = new QLineEdit(w);
        signin_pass_->setEchoMode(QLineEdit::Password);
        signin_pass_->setPlaceholderText("passphrase");
        form->addRow("Identity", signin_user_);
        form->addRow("Passphrase", signin_pass_);
        signin_btn_ = new QPushButton("Sign in", w);
        signin_btn_->setDefault(true);
        connect(signin_btn_, &QPushButton::clicked, this, &LoginDialog::onSignInAccept);
        form->addRow("", signin_btn_);

        auto* links = new QHBoxLayout;
        auto* toCreate = new QPushButton("Create new identity", w);
        toCreate->setObjectName("linkBtn");
        toCreate->setFlat(true);
        connect(toCreate, &QPushButton::clicked, this, &LoginDialog::onCreatePane);
        auto* toRecover = new QPushButton("Recover from code", w);
        toRecover->setObjectName("linkBtn");
        toRecover->setFlat(true);
        connect(toRecover, &QPushButton::clicked, this, &LoginDialog::onRecoverPane);
        links->addStretch();
        links->addWidget(toCreate);
        links->addWidget(toRecover);
        links->addStretch();
        form->addRow(links);
        panes_->addWidget(w);
    }

    // ---- Recover pane ---------------------------------------------------
    {
        auto* w = new QWidget(this);
        auto* form = new QFormLayout(w);
        recover_user_ = new QLineEdit(w);
        recover_user_->setPlaceholderText("alice");
        recover_user_->setValidator(new QRegularExpressionValidator(
            QRegularExpression("[A-Za-z0-9._-]{1,32}"), w));
        recover_hex_  = new QPlainTextEdit(w);
        recover_hex_->setPlaceholderText("24-word phrase  OR  64 hex characters");
        recover_hex_->setMaximumHeight(70);
        recover_pass_ = new QLineEdit(w);
        recover_pass_->setEchoMode(QLineEdit::Password);
        recover_pass_->setPlaceholderText("new passphrase (recommended)");
        form->addRow("Username", recover_user_);
        form->addRow("Recovery code", recover_hex_);
        form->addRow("Passphrase", recover_pass_);
        recover_btn_ = new QPushButton("Restore", w);
        recover_btn_->setDefault(true);
        connect(recover_btn_, &QPushButton::clicked, this, &LoginDialog::onRecoverAccept);
        form->addRow("", recover_btn_);

        auto* back = new QPushButton("Back", w);
        back->setObjectName("linkBtn");
        back->setFlat(true);
        connect(back, &QPushButton::clicked, this, [this] {
            show_pane(list_vault_usernames().isEmpty() ? kPaneCreate : kPaneSignIn);
        });
        auto* links = new QHBoxLayout;
        links->addStretch();
        links->addWidget(back);
        links->addStretch();
        form->addRow(links);
        panes_->addWidget(w);
    }

    // Initial pane: sign-in if any vault exists, else create.
    const QStringList vaults = list_vault_usernames();
    for (const auto& u : vaults) signin_user_->addItem(u);
    if (vaults.isEmpty()) {
        show_pane(kPaneCreate);
    } else {
        show_pane(kPaneSignIn);
        signin_pass_->setFocus();
    }
}

LoginDialog::~LoginDialog() {
    sodium_memzero(seed_.data(), seed_.size());
}

void LoginDialog::show_pane(int idx) {
    panes_->setCurrentIndex(idx);
    error_label_->hide();
    if (idx == kPaneCreate) {
        subtitle_->setText("create your local identity");
    } else if (idx == kPaneSignIn) {
        subtitle_->setText("enter your passphrase");
    } else {
        subtitle_->setText("restore from recovery code");
    }
}

void LoginDialog::show_error(const QString& msg) {
    error_label_->setText(msg);
    error_label_->show();
}

void LoginDialog::onCreatePane()  { show_pane(kPaneCreate);  create_user_->setFocus(); }
void LoginDialog::onSignInPane()  { show_pane(kPaneSignIn);  signin_pass_->setFocus(); }
void LoginDialog::onRecoverPane() { show_pane(kPaneRecover); recover_hex_->setFocus(); }

// Argon2id MODERATE costs ~1-2 s of CPU on a desktop. Running it on the
// Qt main thread (as we did originally) freezes the entire window —
// Qt::WaitCursor only changes the icon, the event loop is blocked.
// Every login handler now offloads the KDF to QtConcurrent and resumes on
// the main thread when the future is ready.

namespace {
void busy(QPushButton* b, bool on, const char* label_busy = "working…") {
    if (on) {
        b->setEnabled(false);
        b->setProperty("_orig_text", b->text());
        b->setText(QString::fromUtf8(label_busy));
    } else {
        b->setEnabled(true);
        const QVariant orig = b->property("_orig_text");
        if (orig.isValid()) b->setText(orig.toString());
    }
}
}  // namespace

void LoginDialog::onCreateAccept() {
    const QString user = create_user_->text().trimmed();
    const QString p1   = create_pass1_->text();
    const QString p2   = create_pass2_->text();
    if (user.isEmpty()) { show_error("username required"); return; }
    if (p1.isEmpty())   { show_error("passphrase required"); return; }
    if (p1 != p2)       { show_error("passphrases don't match"); return; }
    if (QFileInfo::exists(vault_path_for(user))) {
        show_error(QString("a vault already exists for '%1' — sign in or pick another username")
                       .arg(user));
        return;
    }
    busy(create_btn_, true, "deriving key…");
    auto id = fb::crypto::Identity::generate();
    const auto sec = id.secret_key();
    Seed seed{};
    std::memcpy(seed.data(), sec.data(), seed.size());

    auto* watcher = new QFutureWatcher<VaultBlob>(this);
    QObject::connect(watcher, &QFutureWatcher<VaultBlob>::finished, this, [this, watcher, user, seed]() {
        std::unique_ptr<QFutureWatcher<VaultBlob>> w(watcher);
        try {
            VaultBlob blob = w->result();
            save_vault_file(vault_path_for(user), blob);
            username_ = user;
            seed_     = seed;
            busy(create_btn_, false);
            accept();
        } catch (const std::exception& e) {
            busy(create_btn_, false);
            show_error(QString::fromStdString(std::string("create failed: ") + e.what()));
        }
    });
    watcher->setFuture(QtConcurrent::run([p1, seed]() { return seal_seed(p1, seed); }));
}

void LoginDialog::onSignInAccept() {
    const QString user = signin_user_->currentText();
    const QString pass = signin_pass_->text();
    if (user.isEmpty()) { show_error("no identity selected"); return; }
    auto blob = load_vault_file(vault_path_for(user));
    if (!blob) { show_error(QString("vault for '%1' not readable").arg(user)); return; }
    busy(signin_btn_, true, "verifying…");

    auto* watcher = new QFutureWatcher<std::optional<Seed>>(this);
    QObject::connect(watcher, &QFutureWatcher<std::optional<Seed>>::finished, this,
        [this, watcher, user]() {
            std::unique_ptr<QFutureWatcher<std::optional<Seed>>> w(watcher);
            auto seed = w->result();
            busy(signin_btn_, false);
            if (!seed) { show_error("wrong passphrase or corrupted vault"); return; }
            username_ = user;
            seed_     = *seed;
            accept();
        });
    watcher->setFuture(QtConcurrent::run(
        [pass, blob_copy = *blob]() { return open_seed(pass, blob_copy); }));
}

void LoginDialog::onRecoverAccept() {
    const QString user = recover_user_->text().trimmed();
    const QString hex  = recover_hex_->toPlainText();
    const QString pass = recover_pass_->text();
    if (user.isEmpty()) { show_error("username required"); return; }
    if (pass.isEmpty()) { show_error("passphrase required (recovery vaults must be encrypted)"); return; }
    // Accept either format: 24-word BIP39 phrase (whitespace present) or
    // 64-char hex (no whitespace). Both decode to the same 32-byte seed.
    std::optional<Seed> seed;
    if (hex.contains(QRegularExpression("\\s"))) {
        seed = phrase_to_seed(hex);
        if (!seed) { show_error("recovery phrase: unknown word, wrong length, or checksum mismatch (typo?)"); return; }
    } else {
        seed = recovery_hex_to_seed(hex);
        if (!seed) { show_error("recovery code: must be 24-word phrase or 64 hex characters"); return; }
    }
    if (QFileInfo::exists(vault_path_for(user))) {
        const auto r = QMessageBox::question(
            this, "Overwrite existing vault?",
            QString("A vault for '%1' already exists on this device. "
                    "Restoring will overwrite it. Proceed?").arg(user),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (r != QMessageBox::Yes) return;
    }
    busy(recover_btn_, true, "deriving key…");

    const Seed seed_copy = *seed;
    auto* watcher = new QFutureWatcher<VaultBlob>(this);
    QObject::connect(watcher, &QFutureWatcher<VaultBlob>::finished, this,
        [this, watcher, user, seed_copy]() {
            std::unique_ptr<QFutureWatcher<VaultBlob>> w(watcher);
            try {
                VaultBlob blob = w->result();
                save_vault_file(vault_path_for(user), blob);
                username_ = user;
                seed_     = seed_copy;
                busy(recover_btn_, false);
                accept();
            } catch (const std::exception& e) {
                busy(recover_btn_, false);
                show_error(QString::fromStdString(std::string("restore failed: ") + e.what()));
            }
        });
    watcher->setFuture(QtConcurrent::run(
        [pass, seed_copy]() { return seal_seed(pass, seed_copy); }));
}

}  // namespace fb::desktop
