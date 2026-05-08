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
#include <memory>
#include <vector>

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

signals:
    // Outbound signal that needs to reach the peer over the ratchet.
    // ChatClient wraps the payload in DmPayload.media_signal and sends
    // it as a normal encrypted DM.
    void sendSignal(int kind, const QByteArray& payload);

    void stateChanged(State s);
    void log(const QString& msg);

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

    void set_state(State s);
    void emit_local_ice(const QString& candidate, const QString& mid, int mline);
};

}  // namespace fb::desktop
