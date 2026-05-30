// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QCheckBox>
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

class CrtOverlay;     // animated CRT scanline/flicker layer (crt_overlay.hpp)
#if FB_HAVE_EMBEDDED_RELAY
class EmbeddedRelay;  // in-app relay on a background thread (embedded_relay.hpp)
#endif

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;   // out-of-line for unique_ptr<EmbeddedRelay>

    // One rendered line in a conversation buffer. Public so the message
    // delegate / item-fill helper can name it. image_bytes empty = text.
    struct Line {
        QString    sender_name;
        QString    sender_seed;
        QString    body;
        qint64     ts_ms;
        bool       is_self;
        bool       is_history;
        QByteArray image_bytes;   // inline image / GIF; empty = text line
        QString    image_mime;
    };

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
    void onAttachClicked();
    void onNewChannelClicked();
    void onInviteClicked();
    void onLeaveClicked();
    void onDmListSelectionChanged();
    void onChannelSelectionChanged();
    void onVerifyClicked();
    // Tier-11 MITM warning: pops a QMessageBox when chat_client detects
    // a peer's pubkey has changed mid-conversation.
    void onPeerPubkeyChanged(const QString& peerLabel,
                              const QByteArray& oldPubkey,
                              const QByteArray& newPubkey);
    // Tier-11 Shamir social-recovery setup wizard. Reads my_username_ +
    // current contacts from dm_list_, hands off to ShamirSetupWizard.
    void onSocialRecoverySetupClicked();
    void appendLog(const QString& s);
    void appendIncoming(const QString& peer_fp, const QString& peer_username,
                        const QString& text);
    void appendIncomingImage(const QString& peer_fp, const QString& peer_username,
                             const QByteArray& content, const QString& mime,
                             const QString& filename);
    void appendChannelIncoming(const QString& channel, const QString& sender_fp, const QString& text);
    void appendChannelIncomingImage(const QString& channel, const QString& sender_fp,
                                    const QByteArray& content, const QString& mime,
                                    const QString& filename);
    void onChannelJoined(const QString& channel);
    void onConnected(const QString& my_fp);
    void onError(const QString& detail);
    void onPeerUsernameResolved(const QString& peer_fingerprint, const QString& username);
    void onChannelCallRoster(const QString& channel, const QStringList& fingerprints);
    void onMuteToggled();
    void onToggleLog();

protected:
    // Keep the click-through CRT overlay sized to + on top of the window.
    void resizeEvent(QResizeEvent* e) override;

private:
    void selectConversation(const QString& key);
    void appendLineToConversation(const QString& key, const Line& l);
    void appendMessage(const QString& key, const QString& sender_name,
                       const QString& sender_seed, const QString& body,
                       qint64 ts_ms, bool is_self, bool is_history);
    void appendImageMessage(const QString& key, const QString& sender_name,
                            const QString& sender_seed,
                            const QByteArray& image_bytes, const QString& mime,
                            qint64 ts_ms, bool is_self, bool is_history = false);
    void rememberDmPeer(const QString& username);
    void updateChatHeader();

    // Login form (top banner).
    QLineEdit*   host_edit_     = nullptr;
    QSpinBox*    port_spin_     = nullptr;
    QLineEdit*   user_edit_     = nullptr;
    QPushButton* connect_btn_   = nullptr;
    QLabel*      status_label_  = nullptr;
    QPushButton* log_toggle_    = nullptr;
    // Optional TLS toggle. When checked, the worker wraps the
    // outbound socket via fb::net::TlsClient. Server must be
    // running with --tls-raw-port + matching --tls-cert/--tls-key.
    // The dev convenience: "TLS (insecure)" skips cert validation
    // — the only sane way to talk to a self-signed localhost
    // server without first installing the cert into the OS trust
    // store. Production deployments use real CA-issued certs and
    // leave the insecure box unchecked.
    QCheckBox*   tls_check_           = nullptr;
    QCheckBox*   wss_check_           = nullptr;
    QCheckBox*   tls_insecure_check_  = nullptr;
    QPushButton* tls_ca_btn_          = nullptr;
    // Path of the user-picked CA file (PEM). Empty = system trust
    // store. Set by clicking tls_ca_btn_ → QFileDialog.
    QString      tls_ca_path_;

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
    // Channel-call extras: a horizontal strip of avatar+label chips for
    // every other participant, plus a self-mute toggle. Hidden along with
    // the banner when no call is active.
    QWidget*     roster_panel_     = nullptr;
    QPushButton* mute_btn_         = nullptr;

    // Compose row.
    QLineEdit*      target_edit_ = nullptr;
    QLabel*         target_hint_ = nullptr;
    QPlainTextEdit* input_edit_  = nullptr;
    QPushButton*    attach_btn_  = nullptr;
    QPushButton*    send_btn_    = nullptr;
    QPushButton*    verify_btn_  = nullptr;

    // Log pane (toggle).
    QWidget*        log_panel_   = nullptr;
    QPlainTextEdit* log_view_    = nullptr;

    // Animated CRT layer (scanlines + flicker), painted over everything.
    // Toggled via View ▸ CRT effects; persisted in QSettings.
    CrtOverlay*     crt_overlay_ = nullptr;

    // In-app relay: runs the network node on a background thread so launching
    // the desktop also hosts the relay. Only present where the relay library is
    // available (FB_HAVE_EMBEDDED_RELAY); pure-client builds (e.g. Windows
    // without fb_relay) compile it out entirely.
#if FB_HAVE_EMBEDDED_RELAY
    std::unique_ptr<EmbeddedRelay> embedded_relay_;
#endif

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

    std::map<QString, QList<Line>> buffers_;
    QString current_conv_;

    std::unique_ptr<ChatClient> client_;
};

}  // namespace fb::desktop
