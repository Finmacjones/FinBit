// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QListWidget>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QString>
#include <QStringList>
#include <QLineEdit>
#include <QSpinBox>
#include <QLabel>

#include <array>
#include <cstdint>
#include <map>
#include <memory>

#include "chat_client.hpp"

namespace fb::desktop {

// "Conversation key" identifies a DM peer or a channel uniquely.
struct ConvKey {
    static QString dm_user(const QString& username)   { return "dm:" + username; }
    static QString dm_pub(const QString& pub_b64)     { return "dm-pub:" + pub_b64; }
    static QString chan(const QString& channel_name)  { return "chan:" + channel_name; }
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

    // Adopt an unlocked identity (from LoginDialog). Pre-fills the username
    // field, displays the fingerprint, and stores the seed for later
    // connect() calls. Caller must invoke before show().
    void adopt_session(const QString& username,
                        const std::array<std::uint8_t, 32>& seed);

    // Test hooks invoked by main.cpp when the FB_AUTO_* env vars are set.
    // Plumb directly into ChatClient bypassing the QInputDialog modals so
    // automation can drive the mesh-call flow end-to-end without a human
    // clicking through dialogs. Production behaviour is unchanged unless
    // the env vars are present.
    void test_create_local_channel(const QString& channel_name);
    void test_invite_peer_to_channel(const QString& channel_name,
                                      const QString& peer_username);
    void test_join_channel_voice(const QString& channel_name);

private slots:
    void onConnectClicked();
    void onShowRecoveryCode();
    void onSignOut();
    void onCallVoiceClicked();
    void onCallVideoClicked();
    void onHangupClicked();
    void onIncomingCall(const QString& peerLabel, const QString& peerFingerprint);
    void onCallStateChanged(const QString& peerLabel, int state);
    void onSendClicked();
    void onNewChannelClicked();
    void onInviteClicked();
    void onLeaveClicked();
    void onDmListSelectionChanged();
    void onChannelSelectionChanged();
    void onVerifyClicked();
    void appendLog(const QString& s);
    void appendIncoming(const QString& peer_fp, const QString& peer_username,
                        const QString& text);
    void appendChannelIncoming(const QString& channel, const QString& sender_fp, const QString& text);
    void onChannelJoined(const QString& channel);
    void onConnected(const QString& my_fp);
    void onError(const QString& detail);
    void onPeerUsernameResolved(const QString& peer_fingerprint, const QString& username);
    void onChannelCallRoster(const QString& channel, const QStringList& fingerprints);
    void onToggleLog();

private:
    void selectConversation(const QString& key);
    void appendMessage(const QString& key, const QString& sender_name,
                       const QString& sender_seed, const QString& body,
                       qint64 ts_ms, bool is_self, bool is_history);
    void rememberDmPeer(const QString& username);
    void updateChatHeader();

    // Login form (top banner).
    QLineEdit*   host_edit_     = nullptr;
    QSpinBox*    port_spin_     = nullptr;
    QLineEdit*   user_edit_     = nullptr;
    QPushButton* connect_btn_   = nullptr;
    QLabel*      status_label_  = nullptr;
    QPushButton* log_toggle_    = nullptr;

    // Server rail (Discord's left-most column).
    QListWidget* server_rail_   = nullptr;
    QLabel*      user_avatar_   = nullptr;
    QLabel*      user_name_lbl_ = nullptr;
    QLabel*      user_fp_lbl_   = nullptr;

    // Channels panel (server name + DMs + channels + buttons).
    QLabel*      channel_panel_header_ = nullptr;
    QListWidget* dm_list_       = nullptr;
    QListWidget* channel_list_  = nullptr;
    QPushButton* new_chan_btn_  = nullptr;
    QPushButton* invite_btn_    = nullptr;
    QPushButton* leave_btn_     = nullptr;

    // Main message area.
    QLabel*      chat_header_title_    = nullptr;
    QLabel*      chat_header_subtitle_ = nullptr;
    QListWidget* messages_      = nullptr;

    // Voice/video chrome.
    QPushButton* call_voice_btn_   = nullptr;
    QPushButton* call_video_btn_   = nullptr;
    QWidget*     call_banner_      = nullptr;
    QLabel*      call_banner_label_ = nullptr;
    QLabel*      remote_video_     = nullptr;   // QImage frames painted here
    QPushButton* hangup_btn_       = nullptr;

    // Compose row.
    QLineEdit*      target_edit_ = nullptr;
    QLabel*         target_hint_ = nullptr;
    QPlainTextEdit* input_edit_  = nullptr;
    QPushButton*    send_btn_    = nullptr;
    QPushButton*    verify_btn_  = nullptr;

    // Log pane (toggle).
    QWidget*        log_panel_   = nullptr;
    QPlainTextEdit* log_view_    = nullptr;

    QString my_fingerprint_;
    QString my_username_;
    // Channel name we've issued RoomJoin for (empty if not in a channel
    // call). Used by the Hang up button to know whether to send RoomLeave
    // in addition to / instead of the 1:1 hangup_call().
    QString active_channel_call_;
    // 32-byte Ed25519 seed unlocked by LoginDialog; fed to ChatClient on
    // connect. Held in memory only — never written to anything but the
    // .vault file (encrypted) at LoginDialog creation time.
    std::array<std::uint8_t, 32> my_seed_{};

    struct Line {
        QString sender_name;
        QString sender_seed;
        QString body;
        qint64  ts_ms;
        bool    is_self;
        bool    is_history;
    };
    std::map<QString, QList<Line>> buffers_;
    QString current_conv_;

    std::unique_ptr<ChatClient> client_;
};

}  // namespace fb::desktop
