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

class MediaCall;   // wired by start_call_to_pub; full def in media_call.hpp

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

    // TLS-enabled connect. When `use_tls` is true, the worker wraps
    // the outbound socket in fb::net::TlsClient — the same wire
    // protocol travels over an encrypted channel, suitable for
    // running on a likely-open port like 443. `ca_file` is a PEM CA
    // bundle (empty = system trust store); `insecure_skip_verify`
    // disables cert validation entirely (dev / self-signed only —
    // never use against a real server). `sni_hostname` overrides
    // the SNI sent during the TLS handshake; defaults to `host`.
    //
    // When `use_wss` is true (implies use_tls), the worker performs a
    // real RFC 6455 WebSocket upgrade after the TLS handshake and
    // frames traffic as masked WS binary messages — wire-identical to
    // a browser hitting the relay's --tls-port (Tier-2 censorship
    // mimicry; see docs/censorship-resistance.md). Also auto-enabled
    // by the FB_WSS=1 environment variable.
    void connect_tls(const QString& host, std::uint16_t port,
                      const QString& user,
                      const std::array<std::uint8_t, 32>& seed,
                      bool use_tls,
                      const QString& ca_file,
                      bool insecure_skip_verify,
                      const QString& sni_hostname,
                      bool use_wss = false);

    // Send a DM to `peer` (must be a registered username). Safe to call from
    // the UI thread; queues onto the worker.
    void send_to_peer(const QString& peer, const QString& text);

    // Send an inline image / GIF / small file to `peer`. `content` must be
    // <= fb::config::kMaxInlineAttachmentBytes (256 KiB) — returns false
    // (and emits errorOccurred) otherwise. Rides the same ratchet path as
    // a text DM. Safe to call from the UI thread.
    bool send_image_to_peer(const QString& peer, const QString& mime,
                            const QString& filename, const QByteArray& content);

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

    // Send an inline image / GIF to a channel. Same 256 KiB cap as DMs.
    // The image rides the channel's SenderKeys/MLS group encryption as an
    // attachment-framed body (so the relay stays blind). Returns false +
    // emits errorOccurred on overflow.
    bool send_image_to_channel(const QString& name, const QString& mime,
                               const QString& filename, const QByteArray& content);

    // Create a channel locally — generate own SenderKeys chain + subscribe,
    // but DON'T write a distribution file or DM any peer. This is the
    // initial "+" flow in the desktop UI: the user creates the channel,
    // then optionally invites peers separately via invite_peer_to_channel().
    //
    // `use_mls` opts the channel into RFC 9420 MLS encryption instead of
    // SenderKeys. For an MLS channel the SenderKeys distribution is
    // still generated (it's harmless and lets the channel fall back to
    // SenderKeys if a peer has no MLS support yet) but the per-channel
    // crypto flag is recorded so the receive path can pick the right
    // decoder when MLS-protected envelopes start arriving. Only honoured
    // when fb_core was built with FB_FEATURE_MLS=ON; on a stub build
    // the flag is recorded but every actual MLS operation throws and
    // SenderKeys remains the runtime cipher.
    void create_local_channel(const QString& name, bool use_mls = false);

    // In-band invite: create the channel locally if needed, then DM the
    // current SenderKeysDistribution to `peer` so they can decrypt future
    // channel messages without exchanging a file.
    void invite_peer_to_channel(const QString& channel_name, const QString& peer);

    // MLS-channel invite. Sends an MlsInviteRequest to `peer` over the
    // existing pairwise Double Ratchet; the receiver's auto-responder
    // (wired in chat_client.cpp's mlsInviteRequestReceived handler)
    // generates a PendingMlsJoin, replies with their KeyPackage, and
    // we close the loop with add_member + Welcome (also auto). The
    // channel must already exist locally as an MLS channel
    // (created via create_local_channel(name, /*use_mls=*/true)).
    void invite_peer_to_mls_channel(const QString& channel_name,
                                     const QString& peer);

    // Leave a channel: send ChannelUnsubscribe to the server, drop in-memory
    // state, and forget all on-disk traces (chan_state, chan_peers, chan_inbox,
    // and the persisted GroupSession blob).
    void leave_channel(const QString& channel_name);

    // 1:1 voice / video calls (gstreamer webrtcbin underneath).
    //   start_call         — initiate; surfaces stateChanged events.
    //   accept_call        — answer an inbound call after incomingCall fires.
    //   decline_call       — refuse an inbound call.
    //   hangup_call        — tear down the active call (any state).
    // Only one 1:1 call at a time is supported in v0.
    void start_call(const QString& peer_username, bool with_video);
    void accept_call(bool with_video);
    void decline_call();
    void hangup_call();

    // Channel voice calls (full-mesh v0). join_channel_call sends RoomJoin
    // with the channel's group_id; the server replies with RoomRoster on
    // every join/leave from then on. Mesh dialing of per-peer MediaCalls
    // happens automatically on roster deltas (added in a follow-up pass —
    // currently this just plumbs the protocol).
    void join_channel_call(const QString& channel_name, bool with_video);
    void leave_channel_call(const QString& channel_name);

    // MLS (RFC 9420) handshake — DM-delivered protocol messages that
    // ride the same Double Ratchet machinery as text. The four-step
    // in-band invite is:
    //   1. Inviter calls send_mls_invite_request(joiner, channel_id,
    //      channel_name).
    //   2. Joiner sees mlsInviteRequestReceived, generates a
    //      PendingMlsJoin via MlsGroup::start_join, and replies with
    //      send_mls_key_package(inviter, channel_id, kp_bytes).
    //   3. Inviter sees mlsKeyPackageReceived, calls add_member, and
    //      replies with send_mls_welcome(joiner, channel_id, name,
    //      welcome_bytes). For each EXISTING member they also call
    //      send_mls_commit(member, channel_id, commit_bytes).
    //   4. Joiner sees mlsWelcomeReceived and calls
    //      PendingMlsJoin::complete(welcome).
    // The wiring in this header just plumbs each message through the
    // ratchet — actually orchestrating an MlsGroup on top of the
    // signals lives in the migration step (#157).
    void send_mls_invite_request(const QString& peer,
                                  const QByteArray& channel_id,
                                  const QString& channel_name);
    void send_mls_key_package(const QString& peer,
                               const QByteArray& channel_id,
                               const QByteArray& key_package);
    void send_mls_welcome(const QString& peer,
                           const QByteArray& channel_id,
                           const QString& channel_name,
                           const QByteArray& welcome);
    void send_mls_commit(const QString& peer,
                          const QByteArray& channel_id,
                          const QByteArray& commit);

    // Mute / un-mute outbound audio on every active call. Affects both
    // 1:1 calls and every mesh leg simultaneously — the user clicking
    // Mute in the chat banner expects to be silent to ALL peers.
    void set_self_muted(bool muted);
    [[nodiscard]] bool self_muted() const;

    // Stop the worker and release sockets. Blocks until the thread exits.
    void disconnect();

    // ---- Tier-11 MITM verification surface ----
    //
    // The "Verify identity" UI dialog calls these. The safety number is
    // 12 groups of 5 digits — both peers compute the same string and
    // compare aloud / via QR; matching numbers prove no MITM has
    // substituted either pubkey. The verified flag is per-peer and
    // currently in-memory (sqlite persistence is a focused follow-on);
    // it drives the UI's ✓ badge.
    [[nodiscard]] QString    safetyNumberFor(const QByteArray& peerPub) const;
    [[nodiscard]] bool       isPeerVerified(const QByteArray& peerPub) const;
    void                     setPeerVerified(const QByteArray& peerPub, bool verified);
    [[nodiscard]] QByteArray myIdentityPubkey() const;
    [[nodiscard]] QString    myFingerprint() const;

    // ---- Tier-11 Shamir social recovery ----
    //
    // Setup-side: enqueue a ShamirSharePush DM to a trusted contact.
    // The contact's chat_client persists the share to its sqlite store
    // (shamir_held_shares table) and notifies the user via the
    // shamirShareReceived signal.
    //
    // Recovery-side: enqueue a ShamirShareRequest DM to a trustee.
    // The trustee's UI prompts them with shamirShareRequestReceived;
    // if they approve, their client sends back a ShamirSharePush
    // carrying the held share.
    //
    // Both methods route via the existing PendingSend queue (username
    // identifies the recipient — the worker does the key-fetch +
    // ratchet bootstrap as needed). Take a username rather than a raw
    // pubkey so they integrate cleanly with how the rest of chat_client
    // addresses peers; the UI's wizard picks contacts from the contact
    // list (already keyed by username).
    void sendShamirShareTo(const QString&    peerUsername,
                            const QByteArray& share,
                            quint64           setupId,
                            quint32           threshold,
                            quint32           total,
                            const QString&    label);
    void requestShamirShareFrom(const QString&    peerUsername,
                                  quint64           setupId,
                                  const QString&    reason);

    // History entry returned by load_recent_history().
    struct HistoryEntry {
        bool        outgoing;        // true = me → peer; false = peer → me
        QString     peer_fingerprint;
        // Resolved registered username for the peer, if the local
        // peer_name_cache has it. Empty when only the fingerprint is
        // known — UI falls back to displaying the fingerprint.
        QString     peer_username;
        QString     text;
        std::int64_t timestamp_ms;
        // Set when the row was a persisted attachment (framed in the
        // store). image_bytes empty ⇒ a normal text row.
        QByteArray  image_bytes;
        QString     image_mime;
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
        QByteArray   image_bytes;   // set for persisted attachment rows
        QString      image_mime;
    };
    std::vector<ChannelHistoryEntry> load_recent_channel_history(
        const QString& channel_name, std::size_t limit);

    // Cached DM peers (username learned, e.g. when YOU typed it as a target).
    struct CachedPeer { QString username; };
    std::vector<CachedPeer> cached_dm_peers();

signals:
    void connected(QString fingerprint);
    void log(QString line);

    // Tier-11 MITM detection — fired when an already-known peer's
    // identity pubkey appears as a different value (e.g. a key-fetch
    // response carries a pubkey distinct from the one a previously-
    // verified session was bound to). The UI shows a "identity
    // changed — re-verify in person" banner and clears the verified
    // flag for that peer. `peerLabel` is whatever human-readable
    // identifier we have (username if cached, else fingerprint).
    void peerPubkeyChanged(QString peerLabel,
                            QByteArray oldPubkey,
                            QByteArray newPubkey);

    // Tier-11 Shamir social recovery — receive-side notifications.
    // shamirShareReceived: a peer DM'd us their share for safekeeping.
    //   The trustee's chat_client has already persisted to the sqlite
    //   store; this signal lets the UI confirm "you're now holding a
    //   share for <peer>".
    // shamirShareRequestReceived: a peer is asking us to send back the
    //   share we're holding. The UI prompts the user; on approval, the
    //   caller calls sendShamirShareTo with the share looked up from
    //   the store (load_shamir_share).
    void shamirShareReceived(QString    peerFingerprint,
                              QByteArray peerPubkey,
                              quint64    setupId,
                              quint32    threshold,
                              quint32    total,
                              QString    label);
    void shamirShareRequestReceived(QString    peerFingerprint,
                                     QByteArray peerPubkey,
                                     quint64    setupId,
                                     QString    reason);
    // MLS handshake inbound — one signal per DmPayload variant. The
    // chat client just surfaces these; orchestration (calling
    // MlsGroup::add_member, completing PendingMlsJoin, applying
    // commits, broadcasting to existing members) lives outside.
    void mlsInviteRequestReceived(QString peerFingerprint, QByteArray channelId,
                                    QString channelName);
    void mlsKeyPackageReceived(QString peerFingerprint, QByteArray channelId,
                                QByteArray keyPackage);
    void mlsWelcomeReceived(QString peerFingerprint, QByteArray channelId,
                              QString channelName, QByteArray welcome);
    void mlsCommitReceived(QString peerFingerprint, QByteArray channelId,
                             QByteArray commit);
    // Inbound DM. `peerUsername` is the resolved registered username if the
    // local cache has it (so the UI can file the message under "dm:<user>"
    // immediately rather than under the fingerprint and migrating later);
    // empty string means "not yet known — show the fingerprint until
    // peerUsernameResolved arrives".
    void messageReceived(QString peerFingerprint, QString peerUsername, QString text);
    // Inbound inline attachment (image / GIF / small file) from a DM peer.
    // `content` is the raw file bytes; render inline (QImage / QMovie).
    void imageReceived(QString peerFingerprint, QString peerUsername,
                       QByteArray content, QString mime, QString filename);
    void channelMessageReceived(QString channelName, QString senderFingerprint, QString text);
    // Inbound inline attachment in a channel.
    void channelImageReceived(QString channelName, QString senderFingerprint,
                              QByteArray content, QString mime, QString filename);
    void channelJoined(QString channelName);
    // Server resolved a sender pubkey to a registered username. Emitted on
    // every UsernameLookupResponse with found=true. UI repaints any rows
    // that previously showed the fingerprint.
    void peerUsernameResolved(QString peerFingerprint, QString username);
    // Voice/video. peerLabel is a "peer-XXXX" short hex if the username
    // hasn't been resolved yet.
    void incomingCall(QString peerLabel, QString peerFingerprint);
    void callStateChanged(QString peerLabel, int state /*MediaCall::State*/);
    // Channel voice room roster — fires on every server-side membership
    // change for any channel we've joined a call on. `participants` carries
    // each member's fingerprint (resolved later to username if cached).
    void channelCallRoster(QString channelName, QStringList participantFingerprints);
    // Forwarded from MediaCall::remoteVideoFrame so MainWindow can paint
    // without taking a direct dependency on the GStreamer wrapper.
    void remoteVideoFrame(QImage frame);
    void errorOccurred(QString detail);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    // Internal: spin up a MediaCall to `peer_pub`, wire its signals, and
    // set room_id on the entry so room-leave knows to tear it down. Used
    // both by the public start_call(username) wrapper and by mesh-dial on
    // RoomRoster delta. Returns true if the call was created (false if a
    // call to this peer was already in progress).
    bool start_call_to_pub(const std::array<std::uint8_t, 32>& peer_pub,
                           const QString& display_label,
                           bool with_video,
                           const std::string& room_id);

    // Active-speaker (Lever A): connect a new call's audioLevel signal to
    // the room-wide level map, and recompute who stays audible vs gated.
    void wire_call_levels(MediaCall* call, const std::string& peer_key);
    void reselect_active_speakers();

    // Forwarder role (Lever B §4): create (once) the RoomForwarder we run for
    // `room_id` because we were elected its forwarder, and connect its
    // signals to the media-signal queue. Runs on the UI thread.
    void ensure_room_forwarder(const std::string& room_id);
};

}  // namespace fb::desktop
