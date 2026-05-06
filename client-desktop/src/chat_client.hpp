// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QImage>

// Thin Qt-friendly wrapper around the fb::core stack: connect to the relay,
// register identity, exchange Double-Ratchet DMs with a single peer.
//
// All network I/O happens on a background thread. Inbound messages are
// surfaced via Qt signals so the UI thread can paint them safely.

#include <QObject>
#include <QString>

#include <cstdint>
#include <memory>
#include <vector>

namespace fb::desktop {

class ChatClient : public QObject {
    Q_OBJECT

public:
    explicit ChatClient(QObject* parent = nullptr);
    ~ChatClient() override;

    // Start the background worker. Connects to `host:port`, sends ClientHello
    // as `user`, uploads a prekey bundle. Idempotent — second call with
    // running worker is a no-op.
    //
    // `seed` is the 32-byte Ed25519 seed that defines this user's identity
    // — it MUST be the seed already paired with `user` on the relay (the
    // server enforces username/identity binding via challenge-response and
    // will refuse the connection with USERNAME_TAKEN if the pair is wrong).
    // Caller obtains the seed from LoginDialog.
    void connect(const QString& host, std::uint16_t port, const QString& user,
                 const std::array<std::uint8_t, 32>& seed);

    // Send a DM to `peer` (must be a registered username). Safe to call from
    // the UI thread; queues onto the worker.
    void send_to_peer(const QString& peer, const QString& text);

    // Channels (Phase 1).
    //   create_channel — generate own SenderKeys chain, write distribution to
    //                    `dist_file_path`, subscribe to channel.
    //   join_channel   — read distribution from `dist_file_path`, subscribe.
    //   send_to_channel — encrypt with our chain and publish to the channel.
    // Channel id is derived from `name` via crypto_generichash (matches the
    // fb-cli channel mode).
    void create_channel(const QString& name, const QString& dist_file_path);
    void join_channel(const QString& name, const QString& dist_file_path);
    void send_to_channel(const QString& name, const QString& text);

    // Create a channel locally — generate own SenderKeys chain + subscribe,
    // but DON'T write a distribution file or DM any peer. This is the
    // initial "+" flow in the desktop UI: the user creates the channel,
    // then optionally invites peers separately via invite_peer_to_channel().
    void create_local_channel(const QString& name);

    // In-band invite: create the channel locally if needed, then DM the
    // current SenderKeysDistribution to `peer` so they can decrypt future
    // channel messages without exchanging a file.
    void invite_peer_to_channel(const QString& channel_name, const QString& peer);

    // Leave a channel: send ChannelUnsubscribe to the server, drop in-memory
    // state, and forget all on-disk traces (chan_state, chan_peers, chan_inbox,
    // and the persisted GroupSession blob).
    void leave_channel(const QString& channel_name);

    // 1:1 voice / video calls (gstreamer webrtcbin underneath).
    //   start_call         — initiate; surfaces stateChanged events.
    //   accept_call        — answer an inbound call after incomingCall fires.
    //   decline_call       — refuse an inbound call.
    //   hangup_call        — tear down the active call (any state).
    // Only one call at a time is supported in v0.
    void start_call(const QString& peer_username, bool with_video);
    void accept_call(bool with_video);
    void decline_call();
    void hangup_call();

    // Stop the worker and release sockets. Blocks until the thread exits.
    void disconnect();

    // History entry returned by load_recent_history().
    struct HistoryEntry {
        bool        outgoing;        // true = me → peer; false = peer → me
        QString     peer_fingerprint;
        QString     text;
        std::int64_t timestamp_ms;
    };

    // Snapshot of the last `limit` rows from inbox + outbox merged in time
    // order. Safe to call after connected() fires.
    std::vector<HistoryEntry> load_recent_history(std::size_t limit);

    // Per-channel history snapshot (most recent `limit`, ordered oldest→newest
    // for direct UI append).
    struct ChannelHistoryEntry {
        QString      sender_fingerprint;
        bool         is_self;
        QString      text;
        std::int64_t timestamp_ms;
    };
    std::vector<ChannelHistoryEntry> load_recent_channel_history(
        const QString& channel_name, std::size_t limit);

    // Cached DM peers (username learned, e.g. when YOU typed it as a target).
    struct CachedPeer { QString username; };
    std::vector<CachedPeer> cached_dm_peers();

signals:
    void connected(QString fingerprint);
    void log(QString line);
    // Inbound DM. `peerUsername` is the resolved registered username if the
    // local cache has it (so the UI can file the message under "dm:<user>"
    // immediately rather than under the fingerprint and migrating later);
    // empty string means "not yet known — show the fingerprint until
    // peerUsernameResolved arrives".
    void messageReceived(QString peerFingerprint, QString peerUsername, QString text);
    void channelMessageReceived(QString channelName, QString senderFingerprint, QString text);
    void channelJoined(QString channelName);
    // Server resolved a sender pubkey to a registered username. Emitted on
    // every UsernameLookupResponse with found=true. UI repaints any rows
    // that previously showed the fingerprint.
    void peerUsernameResolved(QString peerFingerprint, QString username);
    // Voice/video. peerLabel is a "peer-XXXX" short hex if the username
    // hasn't been resolved yet.
    void incomingCall(QString peerLabel, QString peerFingerprint);
    void callStateChanged(QString peerLabel, int state /*MediaCall::State*/);
    // Forwarded from MediaCall::remoteVideoFrame so MainWindow can paint
    // without taking a direct dependency on the GStreamer wrapper.
    void remoteVideoFrame(QImage frame);
    void errorOccurred(QString detail);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::desktop
