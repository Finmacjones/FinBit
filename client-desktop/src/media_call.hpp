// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// 1:1 voice / video call backed by GStreamer's webrtcbin element.
//
// Design parity with the web client (client-web/ui/media_call.js):
//   * Real WebRTC — webrtcbin handles SDP / ICE / DTLS-SRTP for us.
//     A web client speaking RTCPeerConnection on the other end will
//     interoperate without changes.
//   * Signaling tunneled through the existing Double Ratchet DM via
//     DmPayload.media_signal — SDP / ICE never leave plaintext to the
//     relay or any TURN server.
//   * SFrame layer: NOT included in this round (P2P + DTLS-SRTP gives
//     the same hop-by-hop confidentiality; SFrame matters only when we
//     add an SFU and want frame-level encryption past it).
//
// All GStreamer interaction stays inside this file — the rest of the
// desktop client only talks to the Qt signal/slot surface.

#include <QImage>
#include <QObject>
#include <QString>

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace fb::media {
class RoomKeyRegistry;
}

namespace fb::desktop {

class MediaCall : public QObject {
    Q_OBJECT
public:
    enum class State { kIdle, kRinging, kConnecting, kLive, kClosed };
    Q_ENUM(State)

    enum class SignalKind {
        kOffer    = 1,
        kAnswer   = 2,
        kIce      = 3,
        kHangup   = 4,
        kSframeKey = 5,
    };
    Q_ENUM(SignalKind)

    MediaCall(QObject* parent = nullptr);
    ~MediaCall() override;

    // ---- public lifecycle (mirrors CallSession in media_call.js) -------

    // Optional: install the per-call SFrame base key BEFORE start_outgoing
    // / accept_incoming so the encoded-frame send/recv probes seal/open
    // every Opus and VP8 buffer. Leave un-set and the call falls back to
    // DTLS-SRTP only (still confidential P2P, just not opaque to a future
    // SFU). The call_id (16 bytes) and shared secret (32 bytes from X3DH)
    // are derived by ChatClient and combined into base_key via
    //   HKDF(shared, info = "FinBit-SFrame-call-v1-" || hex(call_id))
    // matching the web client's media_call.js exactly.
    void set_sframe_context(const std::array<std::uint8_t, 32>& shared_secret,
                            const std::array<std::uint8_t, 16>& call_id);

    // Forwarded-room keying (Lever B, docs/gstreamer-relay-spec.md §6A).
    // Supersedes the 1:1 set_sframe_context: instead of one shared per-call
    // base key, the send branch seals with K_self and each inbound track is
    // opened with that sender's per-room key, both derived on demand from
    // `reg` (a RoomKeyRegistry owned by ChatClient, fed by room_secrets and
    // rotated on membership change). `mid_to_sender` maps each forwarded SDP
    // media section (a=mid:...) to the 32-byte identity pubkey of the member
    // whose stream it carries — built from RoomOffer.track_bindings. The
    // registry must outlive the call.
    void set_room_context(
        fb::media::RoomKeyRegistry* reg,
        std::map<std::string, std::array<std::uint8_t, 32>> mid_to_sender);

    // Start an outbound call. `peer_pub` is the peer's 32-byte Ed25519
    // pubkey (used as the call's stable peer identifier). `with_video`
    // adds a video track from the default camera.
    void start_outgoing(const std::array<std::uint8_t, 32>& peer_pub,
                        bool with_video);

    // Accept an inbound call after we've received the OFFER. Caller must
    // have already invoked receive_offer(sdp).
    void accept_incoming(bool with_video);

    // Inbound signaling. Each is a no-op outside the appropriate state.
    void receive_offer(const QByteArray& sdp);
    void receive_answer(const QByteArray& sdp);
    void receive_ice(const QByteArray& candidate_json);

    // Toggle outbound audio mute. Flips the `mute` property on the
    // pipeline's volume element; the peer receives silence (or zero RTP)
    // until we un-mute. No-op if the pipeline isn't built yet.
    void set_self_muted(bool muted);

    // Gate PLAYBACK of this peer's inbound audio (active-speaker
    // selection, Lever A). Unlike set_self_muted (which silences our
    // outbound mic), this silences what WE hear from this peer —
    // ChatClient mutes non-active speakers in big rooms to cap decode
    // load. No-op until the inbound audio chain exists.
    void set_playback_muted(bool muted);

    // End the call. Sends HANGUP to the peer unless `silent` (used when
    // the peer hung up first).
    void hangup(bool silent = false);

    State state() const { return state_; }
    std::array<std::uint8_t, 32> peer_pub() const { return peer_pub_; }
    QByteArray pending_offer_sdp() const { return pending_offer_; }

    // Internal — used by GStreamer pad-probe callbacks living in the
    // .cpp's anonymous namespace. NOT part of the public ABI.
    bool _sframe_enabled() const { return sframe_enabled_; }
    void* _sframe_ctx_raw();
    // Lets the on_connection_state_changed callback advance state out
    // of kConnecting once webrtcbin reports peer-connection-state =
    // CONNECTED (DTLS-SRTP up + ICE consent). Without this the UI's
    // call banner gets stuck on "connecting" even after media flows.
    void _on_connection_state(int gst_webrtc_peer_state);
    // Raw webrtcbin pointer for the GstPromise change-callbacks that
    // need to call set-local-description on the same element they
    // came from. Earlier code stashed this on `g_object_set_data
    // (G_OBJECT(this), ...)` — but `this` is a QObject, not a GObject,
    // so the assertion failed silently and the lambdas got NULL back,
    // which is why ICE never started.
    void* _webrtc_raw() const;
    // Room-mode accessors used by the pad-probe / pad-added callbacks in the
    // .cpp's anonymous namespace (parallel to _sframe_ctx_raw). NOT ABI.
    bool _room_mode() const { return room_mode_; }
    fb::media::RoomKeyRegistry* _room_registry() const { return room_reg_; }
    // The originating sender's 32 raw pubkey bytes for an inbound track's SDP
    // `mid`, or "" if unknown (caller drops/declines to key that pad).
    std::string _room_sender_for_mid(const std::string& mid) const;

signals:
    // Outbound signal that needs to reach the peer over the ratchet.
    // ChatClient wraps the payload in DmPayload.media_signal and sends
    // it as a normal encrypted DM.
    void sendSignal(int kind, const QByteArray& payload);

    void stateChanged(State s);
    void log(const QString& msg);

    // Inbound-audio RMS (dBFS, ≤0) for this peer, ~5×/s from the `level`
    // element. ChatClient aggregates these across the room to pick the
    // active speakers.
    void audioLevel(double rmsDb);

    // Remote video frame ready for paint. width/height come straight
    // from the GStreamer caps; pixel format is BGRA32 (preconverted by
    // videoconvert in the inbound chain). MainWindow connects this and
    // pushes the QImage into a QLabel.setPixmap().
    void remoteVideoFrame(QImage frame);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    State state_ = State::kIdle;
    std::array<std::uint8_t, 32> peer_pub_{};
    QByteArray pending_offer_;
    bool with_video_ = false;
    bool is_caller_  = false;
    std::vector<QByteArray> pending_ice_;   // buffered until remote desc set

    // SFrame context (only used if set_sframe_context was called).
    bool                          sframe_enabled_ = false;
    std::array<std::uint8_t, 32>  sframe_base_key_{};
    std::uint32_t                 sframe_epoch_ = 1;

    // Forwarded-room keying (set_room_context). When room_mode_ is true the
    // seal/open probes pull keys from room_reg_ instead of a per-call base
    // key; mid_to_sender_ resolves each inbound track's mid → sender pubkey.
    bool                          room_mode_ = false;
    fb::media::RoomKeyRegistry*   room_reg_  = nullptr;   // owned by ChatClient
    std::map<std::string, std::array<std::uint8_t, 32>> mid_to_sender_;

    void set_state(State s);
    void emit_local_ice(const QString& candidate, const QString& mid, int mline);
};

}  // namespace fb::desktop
