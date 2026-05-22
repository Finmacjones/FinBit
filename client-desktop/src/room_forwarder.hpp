// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// RoomForwarder — the peer-side SFU graph (Lever B §4,
// docs/gstreamer-relay-spec.md). The node a room elects as forwarder
// (fb::media::elect_forwarder) runs ONE of these: it terminates a webrtcbin
// per leaf and fans each leaf's single audio stream out to every other leaf
// WITHOUT decoding — it re-payloads SFrame-sealed Opus it can't read, so it
// stays end-to-end blind (it is never handed a key). The wiring plan (who
// relays to whom, with join/leave deltas) is the pure, unit-tested
// fb::media::ForwarderRouting; this class is the GStreamer "muscle" that
// realises it.
//
// HONEST STATUS: this compiles against the same GStreamer fb_desktop already
// links, and follows the element graph in §4 plus the offer/answer/ICE
// patterns from media_call.cpp. It is NOT runtime-verified — a live
// multi-party forwarded call needs multiple ICE endpoints / machines (see
// the loopback + hardware test plan in §8). The dynamic renegotiation here
// is the straightforward "one renegotiation per membership change" form; the
// pre-allocated transceiver-pool optimisation (§5) is a later refinement.
// =============================================================================

#include <QByteArray>
#include <QObject>
#include <QString>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace fb::desktop {

class RoomForwarder : public QObject {
    Q_OBJECT
public:
    using Pub = std::array<std::uint8_t, 32>;

    explicit RoomForwarder(const Pub& room_id, QObject* parent = nullptr);
    ~RoomForwarder() override;

    // A leaf joins. `offer_sdp` is the leaf's RoomOffer (it publishes its mic
    // + recvonly slots). We create its webrtcbin, apply the offer, answer
    // (answerReady), wire its inbound stream into the relay, and fan existing
    // sources to it. ICE is trickled separately via leaf_ice().
    void add_leaf(const Pub& leaf_pub, const QByteArray& offer_sdp);

    // The leaf's answer to a renegotiation OFFER we sent (renegotiateOffer) —
    // e.g. after a new member's track was added to that leaf.
    void leaf_answer(const Pub& leaf_pub, const QByteArray& answer_sdp);

    // Trickled ICE from a leaf.
    void leaf_ice(const Pub& leaf_pub, const QByteArray& candidate_json);

    // A leaf leaves: tear down its webrtcbin + every relay branch touching it.
    void remove_leaf(const Pub& leaf_pub);

    // Tear the whole room down.
    void shutdown();

    [[nodiscard]] std::size_t leaf_count() const;

    // Defined in the .cpp; named here (not the instance, which stays private)
    // only so the GStreamer C-callbacks in the .cpp's anonymous namespace can
    // reference the per-leaf state they're handed as user_data.
    struct Impl;

signals:
    // SDP answer for a leaf's initial RoomOffer → send as RoomAnswer.
    void answerReady(const std::array<std::uint8_t, 32>& leaf_pub,
                     const QByteArray& sdp);
    // A renegotiation OFFER the forwarder generated for a leaf (a member's
    // track was added/removed) → send as a RoomOffer; the leaf replies via
    // leaf_answer().
    void renegotiateOffer(const std::array<std::uint8_t, 32>& leaf_pub,
                          const QByteArray& sdp);
    // Local ICE candidate for a leaf → send as RoomIce.
    void localIce(const std::array<std::uint8_t, 32>& leaf_pub,
                  const QByteArray& candidate_json);
    // For an outbound media section (`mid`) to `subscriber`, which member's
    // stream it carries. ChatClient puts these into that subscriber's
    // RoomOffer.track_bindings so the leaf opens each track with the right
    // sender's per-room SFrame key (§6A.3).
    void trackBinding(const std::array<std::uint8_t, 32>& subscriber,
                      const QString& mid,
                      const std::array<std::uint8_t, 32>& source);
    void log(const QString& msg);

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::desktop
