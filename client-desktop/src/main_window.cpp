// SPDX-License-Identifier: AGPL-3.0-or-later
#include "main_window.hpp"

#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFileDialog>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QListWidgetItem>
#include <QMenuBar>
#include <QMessageBox>
#include <QPixmap>
#include <QSplitter>
#include <QStandardPaths>
#include <QStringList>
#include <QVBoxLayout>
#include <QWidget>

#include "avatar.hpp"
#include "discord_theme.hpp"
#include "bip39.hpp"
#include "identity_vault.hpp"
#include "login_dialog.hpp"
#include "message_delegate.hpp"

namespace fb::desktop {

namespace {

QListWidgetItem* sidebar_item(const QString& seed, const QString& label,
                              int avatar_size, QListWidget* parent) {
    auto* item = new QListWidgetItem(label, parent);
    item->setIcon(QIcon(make_avatar(seed, avatar_size)));
    return item;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), client_(std::make_unique<ChatClient>()) {
    setWindowTitle("FinBit");
    resize(1180, 760);

    // ============================================================
    // Top banner: connect form (Discord doesn't have a visible login
    // bar; we show one until connected, then keep it as a thin status
    // strip the user can hide via the Log toggle).
    // ============================================================
    auto* login_box = new QGroupBox("Connect", this);
    login_box->setObjectName("loginGroup");
    auto* login_l = new QHBoxLayout(login_box);
    login_l->setContentsMargins(12, 6, 12, 12);
    host_edit_ = new QLineEdit("127.0.0.1", login_box);
    host_edit_->setMaximumWidth(140);
    port_spin_ = new QSpinBox(login_box);
    port_spin_->setRange(1, 65535);
    port_spin_->setValue(8765);
    port_spin_->setMaximumWidth(80);
    user_edit_ = new QLineEdit("alice", login_box);
    user_edit_->setMaximumWidth(120);
    connect_btn_ = new QPushButton("Connect", login_box);
    log_toggle_ = new QPushButton("Show log", login_box);
    log_toggle_->setObjectName("secondaryBtn");
    status_label_ = new QLabel("disconnected", login_box);
    status_label_->setObjectName("statusLabel");
    login_l->addWidget(new QLabel("Server", login_box));
    login_l->addWidget(host_edit_);
    login_l->addWidget(new QLabel(":", login_box));
    login_l->addWidget(port_spin_);
    login_l->addSpacing(16);
    login_l->addWidget(new QLabel("User", login_box));
    login_l->addWidget(user_edit_);
    login_l->addWidget(connect_btn_);
    login_l->addStretch(1);
    login_l->addWidget(status_label_);
    login_l->addWidget(log_toggle_);

    // ============================================================
    // Server rail (left-most column, 72px wide).
    // ============================================================
    auto* server_rail = new QWidget(this);
    server_rail->setObjectName("serverRail");
    server_rail->setFixedWidth(72);
    auto* rail_l = new QVBoxLayout(server_rail);
    rail_l->setContentsMargins(0, 0, 0, 0);
    rail_l->setSpacing(0);
    server_rail_ = new QListWidget(server_rail);
    server_rail_->setObjectName("serverRailList");
    server_rail_->setIconSize(QSize(48, 48));
    server_rail_->setSpacing(2);
    server_rail_->setSelectionMode(QAbstractItemView::SingleSelection);
    // Single "Home" item — FinBit doesn't use Discord's per-server channel grouping.
    auto* home = sidebar_item("FinBit", "", 48, server_rail_);
    home->setToolTip("Home — DMs and channels");
    server_rail_->setCurrentItem(home);
    rail_l->addWidget(server_rail_, /*stretch=*/1);

    // ============================================================
    // Channels panel (240px column).
    // ============================================================
    auto* channel_panel = new QWidget(this);
    channel_panel->setObjectName("channelPanel");
    channel_panel->setFixedWidth(240);
    auto* cp_l = new QVBoxLayout(channel_panel);
    cp_l->setContentsMargins(0, 0, 0, 0);
    cp_l->setSpacing(0);

    channel_panel_header_ = new QLabel("FinBit", channel_panel);
    channel_panel_header_->setObjectName("channelPanelHeader");
    cp_l->addWidget(channel_panel_header_);

    auto* dm_label = new QLabel("Direct messages", channel_panel);
    dm_label->setObjectName("sidebarSectionLabel");
    cp_l->addWidget(dm_label);
    dm_list_ = new QListWidget(channel_panel);
    dm_list_->setObjectName("dmList");
    dm_list_->setIconSize(QSize(28, 28));
    dm_list_->setSelectionMode(QAbstractItemView::SingleSelection);
    cp_l->addWidget(dm_list_, /*stretch=*/2);

    auto* chan_label = new QLabel("Channels", channel_panel);
    chan_label->setObjectName("sidebarSectionLabel");
    cp_l->addWidget(chan_label);
    channel_list_ = new QListWidget(channel_panel);
    channel_list_->setObjectName("channelList");
    channel_list_->setIconSize(QSize(20, 20));
    channel_list_->setSelectionMode(QAbstractItemView::SingleSelection);
    cp_l->addWidget(channel_list_, /*stretch=*/3);

    auto* sidebar_btn_row = new QHBoxLayout;
    sidebar_btn_row->setContentsMargins(8, 8, 8, 8);
    sidebar_btn_row->setSpacing(6);
    new_chan_btn_ = new QPushButton("+", channel_panel);
    new_chan_btn_->setToolTip("Create a new channel (use the Invite button to add peers)");
    new_chan_btn_->setEnabled(false);
    new_chan_btn_->setFixedWidth(36);
    invite_btn_ = new QPushButton("Invite", channel_panel);
    invite_btn_->setObjectName("secondaryBtn");
    invite_btn_->setToolTip("Invite a peer to the selected channel");
    invite_btn_->setEnabled(false);
    leave_btn_ = new QPushButton("Leave", channel_panel);
    leave_btn_->setObjectName("dangerBtn");
    leave_btn_->setToolTip("Leave selected channel + forget local state");
    leave_btn_->setEnabled(false);
    sidebar_btn_row->addWidget(new_chan_btn_);
    sidebar_btn_row->addWidget(invite_btn_);
    sidebar_btn_row->addWidget(leave_btn_);
    cp_l->addLayout(sidebar_btn_row);

    // ---- User panel (Discord's bottom-left) ----
    auto* user_panel = new QWidget(channel_panel);
    user_panel->setObjectName("userPanel");
    user_panel->setFixedHeight(56);
    auto* up_l = new QHBoxLayout(user_panel);
    up_l->setContentsMargins(8, 8, 8, 8);
    up_l->setSpacing(8);
    user_avatar_ = new QLabel(user_panel);
    user_avatar_->setFixedSize(32, 32);
    user_avatar_->setPixmap(make_avatar("?", 32));
    auto* up_text_col = new QVBoxLayout;
    up_text_col->setSpacing(0);
    user_name_lbl_ = new QLabel("not connected", user_panel);
    user_name_lbl_->setObjectName("userPanelName");
    user_fp_lbl_   = new QLabel("—", user_panel);
    user_fp_lbl_->setObjectName("userPanelFp");
    up_text_col->addWidget(user_name_lbl_);
    up_text_col->addWidget(user_fp_lbl_);
    up_l->addWidget(user_avatar_);
    up_l->addLayout(up_text_col, /*stretch=*/1);
    cp_l->addWidget(user_panel);

    // ============================================================
    // Main chat area (right of the channels panel).
    // ============================================================
    auto* chat = new QWidget(this);
    chat->setStyleSheet(QString("background:%1;").arg(dc::bg_primary));
    auto* chat_l = new QVBoxLayout(chat);
    chat_l->setContentsMargins(0, 0, 0, 0);
    chat_l->setSpacing(0);

    // Chat header (channel title + subtitle).
    auto* chat_header = new QWidget(chat);
    chat_header->setObjectName("chatHeader");
    chat_header->setFixedHeight(48);
    auto* ch_l = new QHBoxLayout(chat_header);
    ch_l->setContentsMargins(16, 0, 16, 0);
    chat_header_title_    = new QLabel("Welcome", chat_header);
    chat_header_title_->setObjectName("chatHeaderTitle");
    chat_header_subtitle_ = new QLabel("Select a DM or channel from the sidebar.",
                                        chat_header);
    chat_header_subtitle_->setObjectName("chatHeaderSubtitle");
    ch_l->addWidget(chat_header_title_);
    ch_l->addWidget(chat_header_subtitle_);
    ch_l->addStretch(1);
    // Voice / video call buttons. Enabled only when the active conversation
    // is a DM (1:1 calls only in v0). Plain text labels — emoji rendering
    // depends on a font that's not always present, so spell it out.
    call_voice_btn_ = new QPushButton("Call",  chat_header);
    call_voice_btn_->setToolTip("Voice call (1:1 only)");
    call_video_btn_ = new QPushButton("Video", chat_header);
    call_video_btn_->setToolTip("Video call (1:1 only)");
    for (auto* b : {call_voice_btn_, call_video_btn_}) {
        b->setFixedHeight(28);
        b->setStyleSheet("background:#3ba55d; color:white; border:none; "
                          "border-radius:4px; padding:4px 12px; font-weight:600;");
    }
    ch_l->addWidget(call_voice_btn_);
    ch_l->addWidget(call_video_btn_);
    chat_l->addWidget(chat_header);

    // Active-call banner (hidden until a call is ringing/connecting/live).
    call_banner_ = new QWidget(chat);
    call_banner_->setObjectName("callBanner");
    call_banner_->hide();
    auto* cb_l = new QHBoxLayout(call_banner_);
    cb_l->setContentsMargins(12, 6, 12, 6);
    call_banner_label_ = new QLabel("In call", call_banner_);
    call_banner_label_->setStyleSheet("color: white; font-weight: 600;");
    hangup_btn_ = new QPushButton("Hang up", call_banner_);
    cb_l->addWidget(call_banner_label_);
    cb_l->addStretch(1);
    // Remote video preview, embedded in the banner. Hidden until a video
    // frame actually arrives (audio-only calls leave it collapsed).
    remote_video_ = new QLabel(call_banner_);
    remote_video_->setFixedSize(160, 90);
    remote_video_->setStyleSheet("background: #18191c; border-radius: 4px;");
    remote_video_->setScaledContents(true);
    remote_video_->hide();
    cb_l->addWidget(remote_video_);
    cb_l->addWidget(hangup_btn_);
    call_banner_->setStyleSheet(
        "#callBanner { background: #5865f2; }"
        "#callBanner QPushButton { background: rgba(0,0,0,0.25); color: white;"
        "  border: none; border-radius: 4px; padding: 4px 12px; }"
        "#callBanner QPushButton:hover { background: rgba(0,0,0,0.45); }");
    chat_l->addWidget(call_banner_);

    // Message list with the rich delegate.
    messages_ = new QListWidget(chat);
    messages_->setObjectName("messages");
    messages_->setItemDelegate(new MessageDelegate(this));
    messages_->setSelectionMode(QAbstractItemView::NoSelection);
    messages_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    chat_l->addWidget(messages_, /*stretch=*/1);

    // Compose row.
    auto* compose = new QWidget(chat);
    compose->setObjectName("composeRow");
    auto* compose_l = new QHBoxLayout(compose);
    compose_l->setContentsMargins(0, 8, 0, 0);
    target_hint_ = new QLabel("DM", compose);
    target_hint_->setStyleSheet("color: #5865f2; font-weight: 700; padding-right: 4px;");
    target_edit_ = new QLineEdit(compose);
    target_edit_->setPlaceholderText("username  or  #channel");
    target_edit_->setMaximumWidth(220);
    QObject::connect(target_edit_, &QLineEdit::textChanged, this, [this](const QString& t) {
        target_hint_->setText(t.startsWith('#') ? "CHAN" : "DM");
        target_hint_->setStyleSheet(
            t.startsWith('#') ? "color: #faa61a; font-weight: 700; padding-right: 4px;"
                              : "color: #5865f2; font-weight: 700; padding-right: 4px;");
    });
    input_edit_ = new QPlainTextEdit(compose);
    input_edit_->setObjectName("input");
    input_edit_->setMaximumHeight(64);
    input_edit_->setPlaceholderText("Message…");
    send_btn_ = new QPushButton("Send", compose);
    send_btn_->setEnabled(false);
    verify_btn_ = new QPushButton("Verify", compose);
    verify_btn_->setObjectName("secondaryBtn");
    verify_btn_->setToolTip("Show safety-number fingerprints (compare out-of-band)");
    verify_btn_->setEnabled(false);
    compose_l->addWidget(target_hint_);
    compose_l->addWidget(target_edit_);
    compose_l->addWidget(input_edit_, /*stretch=*/1);
    compose_l->addWidget(send_btn_);
    compose_l->addWidget(verify_btn_);
    chat_l->addWidget(compose);

    // ============================================================
    // Log panel — collapsed by default, shown via the "Show log" button.
    // ============================================================
    log_panel_ = new QWidget(this);
    log_panel_->setVisible(false);
    auto* lp_l = new QVBoxLayout(log_panel_);
    lp_l->setContentsMargins(0, 0, 0, 0);
    lp_l->setSpacing(0);
    log_view_ = new QPlainTextEdit(log_panel_);
    log_view_->setObjectName("logView");
    log_view_->setReadOnly(true);
    log_view_->setMaximumHeight(160);
    lp_l->addWidget(log_view_);

    // ============================================================
    // Final assembly: 3-column row + login banner above + log below.
    // ============================================================
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(login_box);
    auto* main_row = new QHBoxLayout;
    main_row->setContentsMargins(0, 0, 0, 0);
    main_row->setSpacing(0);
    main_row->addWidget(server_rail);
    main_row->addWidget(channel_panel);
    main_row->addWidget(chat, /*stretch=*/1);
    root->addLayout(main_row, /*stretch=*/1);
    root->addWidget(log_panel_);
    setCentralWidget(central);

    // ---- Wires ----
    QObject::connect(connect_btn_, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    QObject::connect(send_btn_,    &QPushButton::clicked, this, &MainWindow::onSendClicked);
    QObject::connect(new_chan_btn_, &QPushButton::clicked, this, &MainWindow::onNewChannelClicked);
    QObject::connect(invite_btn_, &QPushButton::clicked, this, &MainWindow::onInviteClicked);
    QObject::connect(leave_btn_, &QPushButton::clicked, this, &MainWindow::onLeaveClicked);
    QObject::connect(channel_list_, &QListWidget::itemSelectionChanged, this,
                     &MainWindow::onChannelSelectionChanged);
    QObject::connect(dm_list_, &QListWidget::itemSelectionChanged, this,
                     &MainWindow::onDmListSelectionChanged);
    QObject::connect(verify_btn_, &QPushButton::clicked, this, &MainWindow::onVerifyClicked);
    QObject::connect(log_toggle_, &QPushButton::clicked, this, &MainWindow::onToggleLog);
    QObject::connect(client_.get(), &ChatClient::log, this, &MainWindow::appendLog);
    QObject::connect(client_.get(), &ChatClient::messageReceived, this,
                     &MainWindow::appendIncoming);
    QObject::connect(client_.get(), &ChatClient::channelMessageReceived, this,
                     &MainWindow::appendChannelIncoming);
    QObject::connect(client_.get(), &ChatClient::channelJoined, this,
                     &MainWindow::onChannelJoined);
    QObject::connect(client_.get(), &ChatClient::connected, this, &MainWindow::onConnected);
    QObject::connect(client_.get(), &ChatClient::errorOccurred, this, &MainWindow::onError);
    QObject::connect(client_.get(), &ChatClient::peerUsernameResolved, this,
                     &MainWindow::onPeerUsernameResolved);
    QObject::connect(client_.get(), &ChatClient::channelCallRoster, this,
                     &MainWindow::onChannelCallRoster);

    // Settings menubar — recovery code + sign out. Lives in the global
    // menu bar (Cmd-comma on macOS) rather than chrome inside the window
    // so we don't disturb the existing 4-column layout.
    auto* identity_menu = menuBar()->addMenu("&Identity");
    auto* recover_act   = identity_menu->addAction("Show recovery &code…");
    auto* signout_act   = identity_menu->addAction("&Sign out");
    QObject::connect(recover_act, &QAction::triggered, this, &MainWindow::onShowRecoveryCode);
    QObject::connect(signout_act, &QAction::triggered, this, &MainWindow::onSignOut);

    QObject::connect(call_voice_btn_, &QPushButton::clicked, this,
                     &MainWindow::onCallVoiceClicked);
    QObject::connect(call_video_btn_, &QPushButton::clicked, this,
                     &MainWindow::onCallVideoClicked);
    QObject::connect(hangup_btn_, &QPushButton::clicked, this,
                     &MainWindow::onHangupClicked);
    QObject::connect(client_.get(), &ChatClient::incomingCall, this,
                     &MainWindow::onIncomingCall);
    QObject::connect(client_.get(), &ChatClient::callStateChanged, this,
                     &MainWindow::onCallStateChanged);
    QObject::connect(client_.get(), &ChatClient::remoteVideoFrame, this,
        [this](const QImage& f) {
            if (f.isNull()) return;
            remote_video_->show();
            remote_video_->setPixmap(QPixmap::fromImage(f));
        });
}

// ============================================================================
// Slots & helpers

void MainWindow::onConnectClicked() {
    // The username comes from the unlocked vault — the editable field is a
    // legacy convenience but the seed binds us to the *vault* username, so
    // overriding it would just produce a USERNAME_TAKEN rejection from the
    // server. Force the field to match the unlocked identity.
    if (my_username_.isEmpty()) {
        status_label_->setText("sign in first");
        status_label_->setStyleSheet("color: #ed4245;");
        return;
    }
    user_edit_->setText(my_username_);
    user_edit_->setReadOnly(true);
    connect_btn_->setEnabled(false);
    status_label_->setText("connecting…");
    status_label_->setStyleSheet("color: #faa61a;");
    user_name_lbl_->setText(my_username_);
    user_avatar_->setPixmap(make_avatar(my_username_, 32));
    client_->connect(host_edit_->text(), static_cast<std::uint16_t>(port_spin_->value()),
                     my_username_, my_seed_);
}

void MainWindow::adopt_session(const QString& username,
                                const std::array<std::uint8_t, 32>& seed) {
    my_username_ = username;
    my_seed_ = seed;
    user_edit_->setText(username);
    user_edit_->setReadOnly(true);
    user_name_lbl_->setText(username);
    user_avatar_->setPixmap(make_avatar(username, 32));
    user_fp_lbl_->setText("(sign in successful — connect to relay)");
}

void MainWindow::onShowRecoveryCode() {
    if (my_username_.isEmpty()) {
        QMessageBox::information(this, "Recovery code", "Sign in first.");
        return;
    }
    const auto r = QMessageBox::warning(
        this, "Show recovery code",
        "The recovery code is the raw seed that authenticates you on the "
        "server. Anyone with the code can impersonate you.\n\n"
        "Reveal it now?",
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (r != QMessageBox::Yes) return;
    Seed s = my_seed_;
    const QString hex    = seed_to_recovery_hex(s);
    const QString phrase = seed_to_phrase(s);
    sodium_memzero(s.data(), s.size());

    QMessageBox box(this);
    box.setWindowTitle("Recovery code");
    box.setText("Save this offline. Pasting either the phrase OR the hex into "
                "FinBit on another device (via Sign in → \"I have a recovery "
                "code\") restores this identity — same fingerprint, same channels.");
    box.setInformativeText(
        QString("<b>24-word phrase (BIP39, friendlier to write):</b>"
                "<pre style=\"font-family:monospace;font-size:11pt;"
                "word-spacing:6px;line-height:1.6;\">%1</pre>"
                "<b>or 64 hex characters:</b>"
                "<pre style=\"font-family:monospace;font-size:10pt;"
                "word-break:break-all;\">%2</pre>")
            .arg(phrase, hex));
    box.setTextFormat(Qt::RichText);
    auto* copy_phrase = box.addButton("Copy phrase", QMessageBox::ActionRole);
    auto* copy_hex    = box.addButton("Copy hex",    QMessageBox::ActionRole);
    box.addButton(QMessageBox::Close);
    box.exec();
    if (box.clickedButton() == copy_phrase) {
        QApplication::clipboard()->setText(phrase);
    } else if (box.clickedButton() == copy_hex) {
        QApplication::clipboard()->setText(hex);
    }
}

void MainWindow::onCallVoiceClicked() {
    if (current_conv_.startsWith("dm:")) {
        const QString peer = current_conv_.section(':', 1);
        client_->start_call(peer, /*with_video=*/false);
        return;
    }
    if (current_conv_.startsWith("chan:")) {
        const QString chan = current_conv_.mid(5);
        client_->join_channel_call(chan, /*with_video=*/false);
        active_channel_call_ = chan;
        call_banner_label_->setText(QString("📞 In #%1 — full-mesh").arg(chan));
        call_banner_->show();
        return;
    }
    QMessageBox::information(this, "Voice call",
        "Open a DM or a channel from the sidebar first.");
}

void MainWindow::onCallVideoClicked() {
    if (current_conv_.startsWith("dm:")) {
        const QString peer = current_conv_.section(':', 1);
        client_->start_call(peer, /*with_video=*/true);
        return;
    }
    if (current_conv_.startsWith("chan:")) {
        const QString chan = current_conv_.mid(5);
        client_->join_channel_call(chan, /*with_video=*/true);
        active_channel_call_ = chan;
        call_banner_label_->setText(QString("📹 In #%1 — full-mesh").arg(chan));
        call_banner_->show();
        return;
    }
    QMessageBox::information(this, "Video call",
        "Open a DM or a channel from the sidebar first.");
}

void MainWindow::onHangupClicked() {
    if (!active_channel_call_.isEmpty()) {
        client_->leave_channel_call(active_channel_call_);
        active_channel_call_.clear();
    }
    client_->hangup_call();
    call_banner_->hide();
}

void MainWindow::onIncomingCall(const QString& peerLabel, const QString& peerFingerprint) {
    QMessageBox box(this);
    box.setWindowTitle("Incoming call");
    box.setText(QString("Incoming call from %1").arg(peerLabel));
    box.setInformativeText(QString("Fingerprint: %1").arg(peerFingerprint));
    auto* accept_voice = box.addButton("Accept (voice)", QMessageBox::AcceptRole);
    auto* accept_video = box.addButton("Accept (video)", QMessageBox::AcceptRole);
    box.addButton("Decline", QMessageBox::RejectRole);
    box.exec();
    if (box.clickedButton() == accept_voice) {
        client_->accept_call(/*with_video=*/false);
    } else if (box.clickedButton() == accept_video) {
        client_->accept_call(/*with_video=*/true);
    } else {
        client_->decline_call();
    }
}

void MainWindow::onCallStateChanged(const QString& peerLabel, int state) {
    // MediaCall::State { kIdle=0, kRinging=1, kConnecting=2, kLive=3, kClosed=4 }
    if (state == 4 /*Closed*/) {
        call_banner_->hide();
        remote_video_->hide();
        remote_video_->clear();
        return;
    }
    QString s;
    switch (state) {
        case 1: s = "ringing"; break;
        case 2: s = "connecting"; break;
        case 3: s = "📞 In call"; break;
        default: s = "call"; break;
    }
    call_banner_label_->setText(QString("%1 with %2").arg(s, peerLabel));
    call_banner_->show();
}

void MainWindow::onSignOut() {
    const auto r = QMessageBox::question(
        this, "Sign out",
        "Sign out of FinBit? The connection will be closed and you'll be "
        "returned to the login screen. Your vault stays on this device.",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (r != QMessageBox::Yes) return;
    if (client_) client_->disconnect();
    sodium_memzero(my_seed_.data(), my_seed_.size());
    my_username_.clear();
    my_fingerprint_.clear();
    user_name_lbl_->setText("not signed in");
    user_fp_lbl_->setText("—");
    user_edit_->clear();
    user_edit_->setReadOnly(false);
    status_label_->setText("disconnected");
    status_label_->setStyleSheet("color: #8e9297;");
    connect_btn_->setEnabled(true);
    LoginDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        adopt_session(dlg.selected_username(), dlg.selected_seed());
    } else {
        QApplication::quit();
    }
}

void MainWindow::appendMessage(const QString& key, const QString& sender_name,
                               const QString& sender_seed, const QString& body,
                               qint64 ts_ms, bool is_self, bool is_history) {
    buffers_[key].push_back({sender_name, sender_seed, body, ts_ms, is_self, is_history});
    if (key == current_conv_) {
        auto* item = new QListWidgetItem;
        item->setData(MessageDelegate::RoleSenderName, sender_name);
        item->setData(MessageDelegate::RoleSenderSeed, sender_seed);
        item->setData(MessageDelegate::RoleBody, body);
        item->setData(MessageDelegate::RoleTimestamp, ts_ms);
        item->setData(MessageDelegate::RoleIsSelf, is_self);
        item->setData(MessageDelegate::RoleIsHistory, is_history);
        messages_->addItem(item);
        messages_->scrollToBottom();
    } else {
        // Visual nudge in the sidebar.
        auto* list = key.startsWith("chan:") ? channel_list_ : dm_list_;
        const QString needle =
            key.startsWith("chan:") ? key.mid(5)
                                     : (key.startsWith("dm:") ? key.mid(3) : key.mid(7));
        for (int i = 0; i < list->count(); ++i) {
            if (list->item(i)->text() == needle) {
                list->item(i)->setForeground(QColor("#faa61a"));
                break;
            }
        }
    }
}

void MainWindow::selectConversation(const QString& key) {
    current_conv_ = key;
    messages_->clear();
    if (key.startsWith("dm:")) {
        chat_header_title_->setText("@" + key.mid(3));
        chat_header_subtitle_->setText("Direct message — end-to-end encrypted");
    } else if (key.startsWith("dm-pub:")) {
        chat_header_title_->setText("@" + key.mid(7).left(11));
        chat_header_subtitle_->setText("DM with unverified peer — fingerprint above");
    } else if (key.startsWith("chan:")) {
        chat_header_title_->setText("# " + key.mid(5));
        chat_header_subtitle_->setText("Channel — sender-keys group encryption");
    }
    auto it = buffers_.find(key);
    if (it != buffers_.end()) {
        for (const auto& line : it->second) {
            auto* item = new QListWidgetItem;
            item->setData(MessageDelegate::RoleSenderName, line.sender_name);
            item->setData(MessageDelegate::RoleSenderSeed, line.sender_seed);
            item->setData(MessageDelegate::RoleBody, line.body);
            item->setData(MessageDelegate::RoleTimestamp, line.ts_ms);
            item->setData(MessageDelegate::RoleIsSelf, line.is_self);
            item->setData(MessageDelegate::RoleIsHistory, line.is_history);
            messages_->addItem(item);
        }
        messages_->scrollToBottom();
    }
    // Clear the unread indicator on this entry.
    auto* list = key.startsWith("chan:") ? channel_list_ : dm_list_;
    const QString needle =
        key.startsWith("chan:") ? key.mid(5)
                                 : (key.startsWith("dm:") ? key.mid(3) : key.mid(7));
    for (int i = 0; i < list->count(); ++i) {
        if (list->item(i)->text() == needle) {
            list->item(i)->setForeground(QColor("#dcddde"));
            break;
        }
    }
}

void MainWindow::rememberDmPeer(const QString& username) {
    if (username.isEmpty()) return;
    const QString key = ConvKey::dm_user(username);
    for (int i = 0; i < dm_list_->count(); ++i) {
        if (dm_list_->item(i)->data(Qt::UserRole).toString() == key) return;
    }
    auto* item = sidebar_item(username, username, 28, dm_list_);
    item->setData(Qt::UserRole, key);
}

void MainWindow::onSendClicked() {
    const auto target = target_edit_->text().trimmed();
    const auto text = input_edit_->toPlainText().trimmed();
    if (target.isEmpty() || text.isEmpty()) return;
    const auto ts = QDateTime::currentMSecsSinceEpoch();
    if (target.startsWith('#')) {
        const auto chan = target.mid(1);
        if (chan.isEmpty()) return;
        appendMessage(ConvKey::chan(chan), my_username_, my_username_, text, ts,
                      /*is_self=*/true, /*is_history=*/false);
        client_->send_to_channel(chan, text);
    } else {
        rememberDmPeer(target);
        appendMessage(ConvKey::dm_user(target), my_username_, my_username_, text, ts,
                      /*is_self=*/true, /*is_history=*/false);
        client_->send_to_peer(target, text);
    }
    input_edit_->clear();
}

void MainWindow::onNewChannelClicked() {
    bool ok = false;
    const QString name = QInputDialog::getText(this, "New channel",
                                               "Channel name:", QLineEdit::Normal,
                                               "general", &ok);
    if (!ok || name.isEmpty()) return;
    // Channel creation no longer also asks for a first peer — that was a
    // confusing two-step modal and the prekey fetch could hang if the
    // chosen username wasn't registered. Use the Invite button afterwards.
    client_->create_local_channel(name);
}

void MainWindow::onInviteClicked() {
    auto* item = channel_list_->currentItem();
    if (!item) {
        QMessageBox::information(this, "Invite peer",
                                 "Pick a channel in the sidebar first.");
        return;
    }
    bool ok = false;
    const QString peer = QInputDialog::getText(
        this, "Invite peer", "Peer username:", QLineEdit::Normal, "", &ok);
    if (!ok || peer.isEmpty()) return;
    client_->invite_peer_to_channel(item->text(), peer);
    appendLog(QString("queued invite %1 -> #%2").arg(peer).arg(item->text()));
}

void MainWindow::onLeaveClicked() {
    auto* item = channel_list_->currentItem();
    if (!item) {
        QMessageBox::information(this, "Leave channel",
                                 "Pick a channel in the sidebar first.");
        return;
    }
    const QString name = item->text();
    if (QMessageBox::question(this, "Leave channel",
                               QString("Leave #%1? Local keys, history, and\n"
                                       "subscription are all deleted.").arg(name)) !=
        QMessageBox::Yes) return;
    client_->leave_channel(name);
    delete channel_list_->takeItem(channel_list_->row(item));
    buffers_.erase(ConvKey::chan(name));
    if (current_conv_ == ConvKey::chan(name)) {
        current_conv_.clear();
        messages_->clear();
        chat_header_title_->setText("Welcome");
        chat_header_subtitle_->setText("Select a DM or channel from the sidebar.");
    }
}

void MainWindow::onDmListSelectionChanged() {
    auto* item = dm_list_->currentItem();
    if (!item) return;
    // Conv key is stored on the item via Qt::UserRole — the visible text
    // can be either a username or a fingerprint depending on whether a
    // username_lookup has come back yet, but the underlying buffer is
    // always reachable via the stable data role.
    QString key = item->data(Qt::UserRole).toString();
    if (key.isEmpty()) key = ConvKey::dm_user(item->text());   // legacy fallback
    selectConversation(key);
    target_edit_->setText(item->text());
}

void MainWindow::onChannelSelectionChanged() {
    auto* item = channel_list_->currentItem();
    if (!item) return;
    selectConversation(ConvKey::chan(item->text()));
    target_edit_->setText("#" + item->text());
    auto& buf = buffers_[ConvKey::chan(item->text())];
    if (buf.isEmpty()) {
        const auto rows = client_->load_recent_channel_history(item->text(), 50);
        for (const auto& r : rows) {
            const QString sender = r.is_self ? my_username_ : r.sender_fingerprint;
            appendMessage(ConvKey::chan(item->text()), sender, r.sender_fingerprint,
                          r.text, r.timestamp_ms, r.is_self, /*is_history=*/true);
        }
    }
}

void MainWindow::appendLog(const QString& s) {
    const QString line = QString("[%1] %2")
                             .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                             .arg(s);
    log_view_->appendPlainText(line);
    // Mirror to stderr so headless / automation runs can capture the
    // call-signaling trace without screen-scraping the QPlainTextEdit.
    if (std::getenv("FB_LOG_TO_STDERR")) {
        std::fprintf(stderr, "[%s] %s\n",
                     my_username_.isEmpty() ? "?" : my_username_.toUtf8().constData(),
                     line.toUtf8().constData());
    }
}

void MainWindow::appendIncoming(const QString& peer_fp, const QString& peer_username,
                                 const QString& text) {
    // Prefer the cached username (carried alongside the fp by ChatClient
    // when the local store already has a name for the sender pubkey) for
    // the conv key + sidebar label, so the recipient sees "alice" right
    // away and a reply targets the username rather than the fingerprint.
    // If the cache misses, fall back to the fp; onPeerUsernameResolved
    // will migrate the entry once the server-side lookup returns.
    const bool have_username = !peer_username.isEmpty();
    const QString display_label = have_username ? peer_username : peer_fp;
    const QString key = have_username ? ConvKey::dm_user(peer_username)
                                      : (QStringLiteral("dm:") + peer_fp);
    QListWidgetItem* item = nullptr;
    for (int i = 0; i < dm_list_->count(); ++i) {
        if (dm_list_->item(i)->data(Qt::UserRole).toString() == key) {
            item = dm_list_->item(i);
            break;
        }
    }
    if (!item) {
        item = sidebar_item(display_label, display_label, 28, dm_list_);
        item->setData(Qt::UserRole, key);
    }
    appendMessage(key, display_label, display_label, text,
                  QDateTime::currentMSecsSinceEpoch(),
                  /*is_self=*/false, /*is_history=*/false);
}

void MainWindow::appendChannelIncoming(const QString& channel, const QString& sender_fp,
                                       const QString& text) {
    appendMessage(ConvKey::chan(channel), sender_fp, sender_fp, text,
                  QDateTime::currentMSecsSinceEpoch(),
                  /*is_self=*/false, /*is_history=*/false);
}

void MainWindow::onChannelJoined(const QString& channel) {
    for (int i = 0; i < channel_list_->count(); ++i) {
        if (channel_list_->item(i)->text() == channel) return;
    }
    sidebar_item(channel, channel, 20, channel_list_);
}

void MainWindow::onConnected(const QString& my_fp) {
    status_label_->setText(QString("connected · %1").arg(my_fp));
    status_label_->setStyleSheet("color: #3ba55d;");
    send_btn_->setEnabled(true);
    new_chan_btn_->setEnabled(true);
    invite_btn_->setEnabled(true);
    leave_btn_->setEnabled(true);
    verify_btn_->setEnabled(true);
    my_fingerprint_ = my_fp;
    user_avatar_->setPixmap(make_avatar(my_fp, 32));
    user_name_lbl_->setText(my_username_);
    user_fp_lbl_->setText(my_fp);

    for (const auto& p : client_->cached_dm_peers()) {
        rememberDmPeer(p.username);
    }

    const auto history = client_->load_recent_history(50);
    for (auto it = history.rbegin(); it != history.rend(); ++it) {
        // Prefer the username when the local cache has resolved it — file
        // history under the same "dm:<username>" buffer the live messages
        // use, and let the existing username sidebar entry (created above
        // by rememberDmPeer) cover this peer rather than spawning a
        // duplicate fingerprint-labeled item.
        const bool have_username = !it->peer_username.isEmpty();
        const QString peer_label = have_username ? it->peer_username
                                                  : it->peer_fingerprint;
        // Match appendIncoming's no-username convention ("dm:<fp>") so a
        // live message arriving for the same peer files into the same
        // buffer / sidebar entry. The legacy "dm-pub:<fp>" key is still
        // recognized in selectConversation / onPeerUsernameResolved for
        // backwards compatibility but is no longer produced here.
        const QString key = have_username
            ? ConvKey::dm_user(it->peer_username)
            : (QStringLiteral("dm:") + it->peer_fingerprint);
        // Sender for the bubble: my username (and avatar seed) for outgoing
        // entries, the peer label for inbound. Without this both directions
        // were rendered as if the peer had said them and the user's own
        // history was visually attributed to the other side.
        const QString sender = it->outgoing ? my_username_ : peer_label;
        appendMessage(key, sender, sender, it->text,
                      it->timestamp_ms, /*is_self=*/it->outgoing, /*is_history=*/true);
        // Only invent a fingerprint-labeled sidebar entry as a fallback
        // when we have no username for this peer at all. Username peers
        // are already represented via cached_dm_peers above.
        if (have_username) continue;
        bool found = false;
        for (int i = 0; i < dm_list_->count(); ++i) {
            const QString role = dm_list_->item(i)->data(Qt::UserRole).toString();
            if (role == key || dm_list_->item(i)->text() == it->peer_fingerprint) {
                found = true; break;
            }
        }
        if (!found) {
            auto* item = sidebar_item(it->peer_fingerprint, it->peer_fingerprint,
                                       28, dm_list_);
            item->setData(Qt::UserRole, key);
        }
    }
}

void MainWindow::onError(const QString& detail) {
    status_label_->setText(QString("error: %1").arg(detail));
    status_label_->setStyleSheet("color: #ed4245;");
    connect_btn_->setEnabled(true);
}

void MainWindow::onPeerUsernameResolved(const QString& peer_fingerprint,
                                         const QString& username) {
    // Sidebar entries created by appendIncoming use a fingerprint-based
    // conv key ("dm:<fp>"); when the username arrives we rename the
    // visible label, switch the data role to the new "dm:<username>"
    // key, and migrate the buffer so future sends from this client
    // (which key by username via rememberDmPeer) match.
    const QString old_key_fp     = ConvKey::dm_user(peer_fingerprint);
    const QString old_key_legacy = ConvKey::dm_pub(peer_fingerprint);   // pre-fix data
    const QString new_key        = ConvKey::dm_user(username);

    for (int i = 0; i < dm_list_->count(); ++i) {
        const QString role = dm_list_->item(i)->data(Qt::UserRole).toString();
        if (role == old_key_fp || role == old_key_legacy ||
            dm_list_->item(i)->text() == peer_fingerprint) {
            dm_list_->item(i)->setText(username);
            dm_list_->item(i)->setData(Qt::UserRole, new_key);
            dm_list_->item(i)->setIcon(QIcon(make_avatar(username, 28)));
            break;
        }
    }
    // Migrate buffer from either of the old keys to the new one.
    for (const QString& old_key : {old_key_fp, old_key_legacy}) {
        auto it = buffers_.find(old_key);
        if (it == buffers_.end()) continue;
        auto& dst = buffers_[new_key];
        for (auto& line : it->second) {
            if (line.sender_name == peer_fingerprint) line.sender_name = username;
            dst.append(line);
        }
        buffers_.erase(it);
        if (current_conv_ == old_key) selectConversation(new_key);
    }
    appendLog(QString("resolved %1 -> %2").arg(peer_fingerprint).arg(username));
}

void MainWindow::onVerifyClicked() {
    QString peer_fp;
    if (current_conv_.startsWith("dm-pub:")) {
        peer_fp = current_conv_.mid(7);
    }
    QString details;
    details += QStringLiteral("Compare these two strings with your peer over a\n"
                              "channel you trust (in person, video, voice). If they\n"
                              "match, no MitM has tampered with the key exchange.\n\n");
    details += QStringLiteral("Your fingerprint:\n   %1\n\n").arg(my_fingerprint_);
    if (peer_fp.isEmpty()) {
        details += QStringLiteral("Peer fingerprint:\n   (select a fingerprint-only DM\n"
                                  "    in the sidebar to see the peer fingerprint)");
    } else {
        details += QStringLiteral("Peer fingerprint:\n   %1").arg(peer_fp);
    }
    QMessageBox::information(this, "Safety numbers", details);
}

void MainWindow::onChannelCallRoster(const QString& channel,
                                      const QStringList& fingerprints) {
    if (channel.isEmpty()) return;
    if (active_channel_call_ != channel) return;   // stale event for another room
    QStringList shown = fingerprints;
    // Drop ourselves from the displayed roster — the banner is for "who
    // ELSE is in the call".
    shown.removeAll(my_fingerprint_);
    if (shown.isEmpty()) {
        call_banner_label_->setText(
            QString("📞 In #%1 — alone (waiting for others)").arg(channel));
    } else {
        call_banner_label_->setText(
            QString("📞 In #%1 — with: %2").arg(channel, shown.join(", ")));
    }
    call_banner_->show();
    appendLog(QString("channel call roster #%1: %2 other(s)")
                  .arg(channel).arg(shown.size()));
}

void MainWindow::test_create_local_channel(const QString& name) {
    if (!client_) return;
    client_->create_local_channel(name);
}

void MainWindow::test_invite_peer_to_channel(const QString& channel_name,
                                              const QString& peer_username) {
    if (!client_) return;
    client_->invite_peer_to_channel(channel_name, peer_username);
}

void MainWindow::test_join_channel_voice(const QString& channel_name) {
    if (!client_) return;
    // Mirror the user clicking Call while a channel is selected.
    active_channel_call_ = channel_name;
    call_banner_label_->setText(QString("📞 In #%1 — full-mesh").arg(channel_name));
    call_banner_->show();
    client_->join_channel_call(channel_name, /*with_video=*/false);
}

void MainWindow::onToggleLog() {
    const bool was_visible = log_panel_->isVisible();
    log_panel_->setVisible(!was_visible);
    log_toggle_->setText(was_visible ? "Show log" : "Hide log");
}

void MainWindow::updateChatHeader() {}

}  // namespace fb::desktop
