// SPDX-License-Identifier: AGPL-3.0-or-later
#include "media_call.hpp"

#ifndef FB_HAVE_GSTREAMER
#  define FB_HAVE_GSTREAMER 1
#endif

#if FB_HAVE_GSTREAMER

#define GST_USE_UNSTABLE_API
#include <gst/gst.h>
#include <gst/app/app.h>
#include <gst/sdp/sdp.h>
#include <gst/webrtc/webrtc.h>

#include <sodium.h>

#include "fb/crypto/hkdf.hpp"
#include "fb/media/sframe.hpp"

#include <atomic>

#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <QStringList>
#include <QUrl>

#include <atomic>
#include <cstring>
#include <mutex>

namespace fb::desktop {

namespace {

// One-time gst_init across the whole process.
std::once_flag g_init_flag;
void ensure_gstreamer() {
    std::call_once(g_init_flag, []() {
        gst_init(nullptr, nullptr);
    });
}

// ICE servers — keep aligned with the web client.
constexpr const char* kStunUrl = "stun://stun.l.google.com:19302";

// Optional TURN server config from environment. Same trio of variables as
// the web client's localStorage keys (FB_TURN_URL / FB_TURN_USER /
// FB_TURN_PASS) so deploys can document one set. Without TURN, calls
// across symmetric NATs (carrier WiFi, hotel networks) silently hang in
// "connecting" — STUN alone can't punch through. The user supplies their
// own TURN server; we don't run one.
QString turn_url_or_empty() {
    const char* env = std::getenv("FB_TURN_URL");
    return env ? QString::fromUtf8(env) : QString();
}
QString turn_user() {
    const char* env = std::getenv("FB_TURN_USER");
    return env ? QString::fromUtf8(env) : QString();
}
QString turn_pass() {
    const char* env = std::getenv("FB_TURN_PASS");
    return env ? QString::fromUtf8(env) : QString();
}

// Build the audio (and optional video) producer pipeline that feeds
// webrtcbin. `add_video` controls whether the video branch is included.
//
// The chosen sources:
//   * audio: pulsesrc (works on PipeWire too via the pipewire-pulse shim)
//   * video: v4l2src — falls back to videotestsrc if the device is missing
//
// Codecs: opus for audio, vp8 for video. Both are mandatory-to-implement
// for browser WebRTC, so the web client will always negotiate them.
GstElement* build_pipeline(bool add_video, GstElement** out_webrtc, QString* err) {
    GstElement* pipe = gst_pipeline_new("call-pipeline");
    GstElement* webrtc = gst_element_factory_make("webrtcbin", "sendrecv");
    if (!webrtc) {
        if (err) *err = "webrtcbin element missing — install gstreamer-plugins-bad";
        gst_object_unref(pipe);
        return nullptr;
    }
    g_object_set(webrtc, "bundle-policy", GST_WEBRTC_BUNDLE_POLICY_MAX_BUNDLE,
                 "stun-server", kStunUrl, nullptr);
    // TURN: webrtcbin's "add-turn-server" signal accepts standard
    // turn://user:pass@host:port URIs. We synthesise that from the env
    // vars so the user can configure once at shell level.
    const QString tu = turn_url_or_empty();
    if (!tu.isEmpty()) {
        const QString user = turn_user();
        const QString pass = turn_pass();
        const QStringList urls = tu.split(',', Qt::SkipEmptyParts);
        for (QString u : urls) {
            u = u.trimmed();
            if (u.isEmpty()) continue;
            // Insert credentials if not already in the URI.
            if (!user.isEmpty() && !u.contains('@')) {
                const int sep = u.indexOf("://");
                if (sep > 0) {
                    u = u.left(sep + 3) +
                        QUrl::toPercentEncoding(user) + ':' +
                        QUrl::toPercentEncoding(pass) + '@' +
                        u.mid(sep + 3);
                }
            }
            gboolean ok = FALSE;
            g_signal_emit_by_name(webrtc, "add-turn-server",
                                  u.toUtf8().constData(), &ok);
        }
    }
    gst_bin_add(GST_BIN(pipe), webrtc);

    // ---- audio branch -------------------------------------------------
    // Trailing-caps shorthand ("rtpopuspay ! application/x-rtp,...") used to
    // work but now trips the parser on GStreamer 1.28+ ("no element
    // 'application'") — the parser tries to instantiate `application` as an
    // element. Use an explicit capsfilter instead; semantically identical
    // and immune to the parser's bin-end edge case.
    {
        // The named `mute_volume` element lets MediaCall::set_self_muted
        // toggle outbound audio without ripping the pipeline down. Other
        // participants stop hearing us instantly; flip back and we resume.
        const gchar* desc =
            "pulsesrc ! audioconvert ! audioresample ! "
            "volume name=mute_volume mute=false ! "
            "queue ! opusenc ! rtpopuspay pt=96 ! "
            "capsfilter caps=application/x-rtp,media=(string)audio,"
            "encoding-name=(string)OPUS,payload=(int)96";
        GError* gerr = nullptr;
        GstElement* abin = gst_parse_bin_from_description(desc, TRUE, &gerr);
        if (!abin) {
            if (err) *err = QString("audio branch: %1").arg(gerr ? gerr->message : "unknown");
            if (gerr) g_error_free(gerr);
            gst_object_unref(pipe);
            return nullptr;
        }
        gst_bin_add(GST_BIN(pipe), abin);
        if (!gst_element_link(abin, webrtc)) {
            if (err) *err = "could not link audio branch to webrtcbin";
            gst_object_unref(pipe);
            return nullptr;
        }
    }

    // ---- video branch (optional) -------------------------------------
    if (add_video) {
        // v4l2src first; if the device is missing we still want SOMETHING
        // negotiated so the call succeeds. videotestsrc is the fallback.
        const gchar* desc =
            "v4l2src ! videoconvert ! videoscale ! "
            "video/x-raw,width=640,height=360,framerate=30/1 ! "
            "queue ! vp8enc deadline=1 cpu-used=4 ! rtpvp8pay pt=97 ! "
            "capsfilter caps=application/x-rtp,media=(string)video,"
            "encoding-name=(string)VP8,payload=(int)97";
        GError* gerr = nullptr;
        GstElement* vbin = gst_parse_bin_from_description(desc, TRUE, &gerr);
        if (!vbin) {
            // Camera not available — fall back to videotestsrc so we don't
            // refuse the call entirely.
            if (gerr) g_error_free(gerr);
            const gchar* fb =
                "videotestsrc is-live=true pattern=ball ! "
                "video/x-raw,width=640,height=360,framerate=30/1 ! "
                "videoconvert ! queue ! vp8enc deadline=1 cpu-used=4 ! rtpvp8pay pt=97 ! "
                "capsfilter caps=application/x-rtp,media=(string)video,"
                "encoding-name=(string)VP8,payload=(int)97";
            vbin = gst_parse_bin_from_description(fb, TRUE, nullptr);
        }
        if (vbin) {
            gst_bin_add(GST_BIN(pipe), vbin);
            gst_element_link(vbin, webrtc);
        }
    }

    *out_webrtc = webrtc;
    return pipe;
}

// Per-call SFrame state. Held by value in Impl so the GStreamer probe
// callback (running on a streaming thread) can fetch+atomic-increment
// the counter without locking back into MediaCall. Wire format docs in
// the seal/open probe definitions further down.
struct SframeProbeCtx {
    std::array<std::uint8_t, 32>  base_key{};
    std::uint32_t                 epoch = 1;
    std::atomic<std::uint64_t>    send_counter{0};
};

}  // namespace

// ---------------------------------------------------------------------------
// Impl: holds GStreamer pipeline + webrtcbin handle. Pointer-stable so we
// can safely capture `this` in C-style g_signal_connect callbacks.
// ---------------------------------------------------------------------------
struct MediaCall::Impl {
    GstElement* pipeline = nullptr;
    GstElement* webrtc   = nullptr;
    GstBus*     bus      = nullptr;
    guint       bus_watch = 0;
    MediaCall*  owner    = nullptr;
    SframeProbeCtx sframe_ctx{};   // populated by set_sframe_context

    ~Impl() {
        if (bus_watch) g_source_remove(bus_watch);
        if (bus)       gst_object_unref(bus);
        if (pipeline) {
            gst_element_set_state(pipeline, GST_STATE_NULL);
            gst_object_unref(pipeline);
        }
    }
};

MediaCall::MediaCall(QObject* parent)
    : QObject(parent), impl_(std::make_unique<Impl>()) {
    ensure_gstreamer();
    impl_->owner = this;
}

MediaCall::~MediaCall() {
    hangup(/*silent=*/true);
}

void MediaCall::set_sframe_context(const std::array<std::uint8_t, 32>& shared_secret,
                                    const std::array<std::uint8_t, 16>& call_id) {
    // Derive per-call base key:
    //   HKDF-SHA256(shared, info = "FinBit-SFrame-call-v1-" || hex(call_id))
    // Matches client-web/ui/media_call.js so calls between desktop and
    // browser can validate each other's frames.
    static constexpr char kHex[] = "0123456789abcdef";
    std::string info = "FinBit-SFrame-call-v1-";
    info.reserve(info.size() + 32);
    for (auto b : call_id) {
        info.push_back(kHex[(b >> 4) & 0xf]);
        info.push_back(kHex[b & 0xf]);
    }
    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(shared_secret.data(), shared_secret.size()));
    auto vec = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(info.data()), info.size()),
        impl_->sframe_ctx.base_key.size());
    std::memcpy(impl_->sframe_ctx.base_key.data(), vec.data(),
                impl_->sframe_ctx.base_key.size());
    impl_->sframe_ctx.epoch = sframe_epoch_;
    impl_->sframe_ctx.send_counter.store(0);
    sframe_enabled_ = true;
    emit log("SFrame enabled (per-call base key derived)");
}

void* MediaCall::_sframe_ctx_raw() { return &impl_->sframe_ctx; }

// ----------------- GStreamer ↔ Qt glue ---------------------------------------

namespace {

// Reschedule a lambda onto the QObject's owner thread (the Qt main thread).
// All inbound webrtcbin signals fire on GLib worker threads.
void post_to_qt(QObject* obj, std::function<void()> fn) {
    QMetaObject::invokeMethod(obj, std::move(fn), Qt::QueuedConnection);
}

void on_negotiation_needed(GstElement* webrtc, gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    post_to_qt(call, [call]() { emit call->log("negotiation-needed: creating OFFER"); });
    GstPromise* promise = gst_promise_new_with_change_func(
        [](GstPromise* p, gpointer u) {
            auto* call_ = static_cast<MediaCall*>(u);
            const GstStructure* reply = gst_promise_get_reply(p);
            GstWebRTCSessionDescription* offer = nullptr;
            gst_structure_get(reply, "offer",
                              GST_TYPE_WEBRTC_SESSION_DESCRIPTION, &offer, nullptr);
            gst_promise_unref(p);
            if (!offer) {
                post_to_qt(call_, [call_]() {
                    emit call_->log("create-offer reply had no 'offer' field");
                });
                return;
            }

            // Set local description and serialise SDP to send to peer.
            GstPromise* set_p = gst_promise_new();
            g_signal_emit_by_name(GST_ELEMENT(call_->_webrtc_raw()),
                                  "set-local-description", offer, set_p);
            gst_promise_interrupt(set_p);
            gst_promise_unref(set_p);

            gchar* sdp_str = gst_sdp_message_as_text(offer->sdp);
            QByteArray sdp_bytes(sdp_str);
            g_free(sdp_str);
            gst_webrtc_session_description_free(offer);

            const int sdp_len = sdp_bytes.size();
            post_to_qt(call_, [call_, sdp_bytes, sdp_len]() {
                emit call_->log(QString("OFFER created (%1 bytes), sending").arg(sdp_len));
                emit call_->sendSignal(static_cast<int>(MediaCall::SignalKind::kOffer), sdp_bytes);
            });
        }, call, nullptr);
    g_signal_emit_by_name(webrtc, "create-offer", nullptr, promise);
}

// =============================================================================
// SFrame: encrypt every encoded audio/video frame with a per-call base
// key derived from the X3DH shared secret + the call_id. Sealed wire
// format matches client-web/ui/media_call.js byte-for-byte:
//   [u32 BE epoch][u64 BE counter][AES-256-GCM ct+tag]
//
// Implemented as GStreamer pad probes that intercept buffers between the
// codec (opusenc / vp8enc) and the RTP payloader on send, and between
// the RTP depayloader and the decoder on receive.
//
// Per-call counter state lives in MediaCall::Impl::sframe_ctx (defined
// near the top — Impl needs the type to be complete).
// =============================================================================

// Send-side: seal each buffer in place with sframe_seal_v1.
GstPadProbeReturn sframe_seal_probe(GstPad* /*pad*/, GstPadProbeInfo* info, gpointer user) {
    auto* ctx = static_cast<SframeProbeCtx*>(user);
    GstBuffer* buf = GST_PAD_PROBE_INFO_BUFFER(info);
    if (!buf) return GST_PAD_PROBE_OK;

    GstMapInfo map{};
    if (!gst_buffer_map(buf, &map, GST_MAP_READ)) return GST_PAD_PROBE_OK;
    const std::uint64_t counter = ctx->send_counter.fetch_add(1);
    std::vector<std::uint8_t> sealed;
    try {
        sealed = fb::media::sframe_seal_v1(
            std::span<const std::uint8_t, 32>(ctx->base_key.data(), 32),
            ctx->epoch, counter,
            std::span<const std::uint8_t>(map.data, map.size));
    } catch (...) {
        gst_buffer_unmap(buf, &map);
        return GST_PAD_PROBE_OK;   // fail open; DTLS-SRTP still protects the link
    }
    gst_buffer_unmap(buf, &map);

    // Replace buffer payload with the sealed bytes.
    GstBuffer* new_buf = gst_buffer_new_allocate(nullptr, sealed.size(), nullptr);
    GstMapInfo wmap{};
    if (gst_buffer_map(new_buf, &wmap, GST_MAP_WRITE)) {
        std::memcpy(wmap.data, sealed.data(), sealed.size());
        gst_buffer_unmap(new_buf, &wmap);
    }
    // Carry over PTS/DTS/duration so the RTP payloader's timing stays correct.
    GST_BUFFER_PTS(new_buf)      = GST_BUFFER_PTS(buf);
    GST_BUFFER_DTS(new_buf)      = GST_BUFFER_DTS(buf);
    GST_BUFFER_DURATION(new_buf) = GST_BUFFER_DURATION(buf);
    GST_BUFFER_FLAGS(new_buf)    = GST_BUFFER_FLAGS(buf);

    GST_PAD_PROBE_INFO_DATA(info) = new_buf;
    gst_buffer_unref(buf);
    return GST_PAD_PROBE_OK;
}

// Recv-side: unseal each buffer in place with sframe_open_v1.  On
// authentication failure (forged or wrong-key frame), drop the buffer.
GstPadProbeReturn sframe_open_probe(GstPad* /*pad*/, GstPadProbeInfo* info, gpointer user) {
    auto* ctx = static_cast<SframeProbeCtx*>(user);
    GstBuffer* buf = GST_PAD_PROBE_INFO_BUFFER(info);
    if (!buf) return GST_PAD_PROBE_OK;

    GstMapInfo map{};
    if (!gst_buffer_map(buf, &map, GST_MAP_READ)) return GST_PAD_PROBE_OK;
    auto opened = fb::media::sframe_open_v1(
        std::span<const std::uint8_t, 32>(ctx->base_key.data(), 32),
        std::span<const std::uint8_t>(map.data, map.size));
    gst_buffer_unmap(buf, &map);
    if (!opened) return GST_PAD_PROBE_DROP;   // forged / tampered / wrong key

    GstBuffer* new_buf = gst_buffer_new_allocate(nullptr, opened->size(), nullptr);
    GstMapInfo wmap{};
    if (gst_buffer_map(new_buf, &wmap, GST_MAP_WRITE)) {
        std::memcpy(wmap.data, opened->data(), opened->size());
        gst_buffer_unmap(new_buf, &wmap);
    }
    GST_BUFFER_PTS(new_buf)      = GST_BUFFER_PTS(buf);
    GST_BUFFER_DTS(new_buf)      = GST_BUFFER_DTS(buf);
    GST_BUFFER_DURATION(new_buf) = GST_BUFFER_DURATION(buf);
    GST_BUFFER_FLAGS(new_buf)    = GST_BUFFER_FLAGS(buf);

    GST_PAD_PROBE_INFO_DATA(info) = new_buf;
    gst_buffer_unref(buf);
    return GST_PAD_PROBE_OK;
}

// Find element by factory name within a bin/pipeline (recursive). Returns
// a borrowed pointer (caller must not unref).
GstElement* find_element_by_factory(GstBin* bin, const gchar* factory_name) {
    GstIterator* it = gst_bin_iterate_elements(bin);
    GValue val = G_VALUE_INIT;
    GstElement* found = nullptr;
    while (!found && gst_iterator_next(it, &val) == GST_ITERATOR_OK) {
        auto* el = GST_ELEMENT(g_value_get_object(&val));
        GstElementFactory* f = gst_element_get_factory(el);
        if (f && std::strcmp(GST_OBJECT_NAME(f), factory_name) == 0) {
            found = el;
        }
        if (!found && GST_IS_BIN(el)) {
            found = find_element_by_factory(GST_BIN(el), factory_name);
        }
        g_value_reset(&val);
    }
    gst_iterator_free(it);
    return found;
}

// Walk the pipeline and install the SFrame seal probe on every encoder
// SRC pad we find (opusenc + vp8enc).  Called once per outbound call
// after the pipeline reaches PLAYING.
void install_sframe_send_probes(GstElement* pipeline, SframeProbeCtx* ctx) {
    for (const gchar* fac : {"opusenc", "vp8enc"}) {
        GstElement* el = find_element_by_factory(GST_BIN(pipeline), fac);
        if (!el) continue;
        GstPad* src = gst_element_get_static_pad(el, "src");
        if (!src) continue;
        gst_pad_add_probe(src, GST_PAD_PROBE_TYPE_BUFFER,
                          sframe_seal_probe, ctx, nullptr);
        gst_object_unref(src);
    }
}

// Same for the recv side: probe the SRC pad of every depayloader so the
// next stage (decoder) sees plaintext encoded frames.
void install_sframe_recv_probe(GstElement* sink_chain, SframeProbeCtx* ctx) {
    for (const gchar* fac : {"rtpopusdepay", "rtpvp8depay"}) {
        GstElement* el = find_element_by_factory(GST_BIN(sink_chain), fac);
        if (!el) continue;
        GstPad* src = gst_element_get_static_pad(el, "src");
        if (!src) continue;
        gst_pad_add_probe(src, GST_PAD_PROBE_TYPE_BUFFER,
                          sframe_open_probe, ctx, nullptr);
        gst_object_unref(src);
    }
}

// appsink → QImage → MediaCall::remoteVideoFrame. Called on a GStreamer
// streaming thread; the QImage carries owned bytes (deep-copied via
// QImage::copy) so the UI thread doesn't have to coordinate with the
// GstSample's lifetime.
GstFlowReturn on_video_sample(GstElement* appsink, gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    GstSample* sample = nullptr;
    g_signal_emit_by_name(appsink, "pull-sample", &sample);
    if (!sample) return GST_FLOW_OK;

    GstCaps* caps = gst_sample_get_caps(sample);
    GstStructure* s = caps ? gst_caps_get_structure(caps, 0) : nullptr;
    int w = 0, h = 0;
    if (s) {
        gst_structure_get_int(s, "width",  &w);
        gst_structure_get_int(s, "height", &h);
    }
    GstBuffer* buf = gst_sample_get_buffer(sample);
    GstMapInfo map{};
    if (w > 0 && h > 0 && buf && gst_buffer_map(buf, &map, GST_MAP_READ)) {
        // BGRA matches QImage::Format_ARGB32 on little-endian systems.
        QImage frame(map.data, w, h, w * 4, QImage::Format_ARGB32);
        QImage owned = frame.copy();   // detach from GStreamer-owned bytes
        gst_buffer_unmap(buf, &map);
        post_to_qt(call, [call, owned]() {
            emit call->remoteVideoFrame(owned);
        });
    }
    gst_sample_unref(sample);
    return GST_FLOW_OK;
}

// Inbound media: when webrtcbin negotiates a remote track, it adds an
// "src_<n>" pad whose caps describe the encoding. Build a depay → decode
// → autoaudiosink/autovideosink chain on the fly and link the new pad
// into it so the peer's audio actually plays / video shows up.
void on_pad_added(GstElement* webrtc, GstPad* new_pad, gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    if (gst_pad_get_direction(new_pad) != GST_PAD_SRC) return;

    GstCaps* caps = gst_pad_get_current_caps(new_pad);
    if (!caps) caps = gst_pad_query_caps(new_pad, nullptr);
    if (!caps) return;
    GstStructure* s = gst_caps_get_structure(caps, 0);
    const gchar* media = gst_structure_get_string(s, "media");
    const gchar* enc   = gst_structure_get_string(s, "encoding-name");

    GstElement* pipe = GST_ELEMENT(gst_element_get_parent(webrtc));
    if (!pipe) { gst_caps_unref(caps); return; }

    const bool is_audio = (media && std::strcmp(media, "audio") == 0) ||
                          (enc   && std::strcmp(enc, "OPUS") == 0);
    const bool is_video = (media && std::strcmp(media, "video") == 0) ||
                          (enc   && std::strcmp(enc, "VP8") == 0);

    const gchar* desc = nullptr;
    if (is_audio) {
        desc = "rtpopusdepay ! opusdec ! audioconvert ! audioresample ! "
               "queue ! autoaudiosink";
    } else if (is_video) {
        // appsink emits "new-sample"; we pull GstSample → BGRA bytes →
        // QImage and signal the UI thread to paint. drop=true / max-
        // buffers=1 stops the pipeline back-pressuring if the UI falls
        // behind on a slow paint cycle.
        desc = "rtpvp8depay ! vp8dec ! videoconvert ! "
               "video/x-raw,format=BGRA ! "
               "queue ! appsink name=remote_video_sink emit-signals=true "
               "sync=false drop=true max-buffers=1";
    } else {
        post_to_qt(call, [call]() {
            emit call->log("inbound pad: unknown caps — ignored");
        });
        gst_caps_unref(caps);
        return;
    }
    gst_caps_unref(caps);

    GError* gerr = nullptr;
    GstElement* sink_chain = gst_parse_bin_from_description(desc, TRUE, &gerr);
    if (!sink_chain) {
        QString err = gerr ? QString::fromUtf8(gerr->message) : "(unknown)";
        if (gerr) g_error_free(gerr);
        post_to_qt(call, [call, err]() { emit call->log("inbound chain build: " + err); });
        return;
    }
    gst_bin_add(GST_BIN(pipe), sink_chain);
    // Install SFrame open-probe BEFORE the chain transitions to PLAYING
    // so the very first buffer through the depayloader gets unsealed.
    if (call->_sframe_enabled()) {
        install_sframe_recv_probe(sink_chain,
            static_cast<SframeProbeCtx*>(call->_sframe_ctx_raw()));
    }
    gst_element_sync_state_with_parent(sink_chain);

    GstPad* sink_pad = gst_element_get_static_pad(sink_chain, "sink");
    if (gst_pad_link(new_pad, sink_pad) != GST_PAD_LINK_OK) {
        post_to_qt(call, [call]() { emit call->log("inbound: pad link failed"); });
    } else {
        post_to_qt(call, [call, is_audio]() {
            emit call->log(is_audio ? "inbound audio playback wired"
                                     : "inbound video display wired");
        });
        // For the video branch: hook the appsink's new-sample signal so
        // each decoded frame becomes a QImage emit.
        if (is_video) {
            GstElement* appsink = gst_bin_get_by_name(GST_BIN(sink_chain),
                                                      "remote_video_sink");
            if (appsink) {
                g_signal_connect(appsink, "new-sample",
                                 G_CALLBACK(on_video_sample), call);
                gst_object_unref(appsink);
            }
        }
    }
    gst_object_unref(sink_pad);
}

// Fires every time webrtcbin's `connection-state` property changes — that's
// the WebRTC PeerConnectionState aggregate over ICE + DTLS-SRTP. Values
// match GstWebRTCPeerConnectionState (new=0, connecting=1, connected=2,
// disconnected=3, failed=4, closed=5). Without this listener the UI banner
// stays "connecting" forever even though media flows fine — set_state()
// to kLive is gated on this signal.
void on_connection_state_changed(GstElement* webrtc, GParamSpec* /*pspec*/,
                                  gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    gint state_int = 0;
    g_object_get(webrtc, "connection-state", &state_int, nullptr);
    post_to_qt(call, [call, state_int]() {
        call->_on_connection_state(state_int);
    });
}

void on_ice_gathering_state_changed(GstElement* webrtc, GParamSpec* /*pspec*/,
                                     gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    gint state_int = 0;
    g_object_get(webrtc, "ice-gathering-state", &state_int, nullptr);
    static const char* names[] = { "new", "gathering", "complete" };
    const char* name = (state_int >= 0 && state_int < 3) ? names[state_int] : "?";
    post_to_qt(call, [call, name]() {
        emit call->log(QString("ice-gathering-state: %1").arg(name));
    });
}

void on_ice_connection_state_changed(GstElement* webrtc, GParamSpec* /*pspec*/,
                                      gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    gint state_int = 0;
    g_object_get(webrtc, "ice-connection-state", &state_int, nullptr);
    static const char* names[] = {
        "new", "checking", "connected", "completed",
        "failed", "disconnected", "closed"
    };
    const char* name = (state_int >= 0 && state_int < 7) ? names[state_int] : "?";
    post_to_qt(call, [call, name]() {
        emit call->log(QString("ice-connection-state: %1").arg(name));
    });
}

void on_signaling_state_changed(GstElement* webrtc, GParamSpec* /*pspec*/,
                                 gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    gint state_int = 0;
    g_object_get(webrtc, "signaling-state", &state_int, nullptr);
    post_to_qt(call, [call, state_int]() {
        emit call->log(QString("signaling-state: %1").arg(state_int));
    });
}

void on_ice_candidate(GstElement* /*webrtc*/, guint mline, gchar* candidate, gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    QString cand_qs = QString::fromUtf8(candidate);
    QJsonObject obj;
    obj["candidate"] = cand_qs;
    obj["sdpMid"] = QString::number(mline);          // best-effort
    obj["sdpMLineIndex"] = static_cast<int>(mline);
    QByteArray payload = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    // Truncate the candidate string for logging — full SDP candidate
    // strings are noisy (host:port + foundation + priority + raddr).
    const QString cand_short = cand_qs.left(60) +
        (cand_qs.size() > 60 ? "…" : "");
    post_to_qt(call, [call, payload, cand_short, mline]() {
        emit call->log(QString("local ICE candidate (mline=%1): %2")
                           .arg(mline).arg(cand_short));
        emit call->sendSignal(static_cast<int>(MediaCall::SignalKind::kIce), payload);
    });
}

gboolean on_bus_message(GstBus*, GstMessage* msg, gpointer user) {
    auto* call = static_cast<MediaCall*>(user);
    switch (GST_MESSAGE_TYPE(msg)) {
        case GST_MESSAGE_ERROR: {
            GError* err = nullptr;
            gchar* dbg = nullptr;
            gst_message_parse_error(msg, &err, &dbg);
            QString s = QString("gst error: %1 (dbg=%2)")
                            .arg(err ? err->message : "?")
                            .arg(dbg ? dbg : "");
            if (err) g_error_free(err);
            g_free(dbg);
            post_to_qt(call, [call, s]() { emit call->log(s); });
            break;
        }
        case GST_MESSAGE_WARNING: {
            GError* err = nullptr;
            gchar* dbg = nullptr;
            gst_message_parse_warning(msg, &err, &dbg);
            QString s = QString("gst warn: %1").arg(err ? err->message : "?");
            if (err) g_error_free(err);
            g_free(dbg);
            post_to_qt(call, [call, s]() { emit call->log(s); });
            break;
        }
        case GST_MESSAGE_EOS:
            post_to_qt(call, [call]() { call->hangup(); });
            break;
        case GST_MESSAGE_STATE_CHANGED: {
            // Only log pipeline-level transitions — every element transition
            // would be noise.
            if (GST_MESSAGE_SRC(msg) &&
                std::strcmp(GST_OBJECT_NAME(GST_MESSAGE_SRC(msg)), "call-pipeline") == 0) {
                GstState old_st, new_st, pend_st;
                gst_message_parse_state_changed(msg, &old_st, &new_st, &pend_st);
                QString s = QString("pipeline state: %1 -> %2")
                                .arg(gst_element_state_get_name(old_st))
                                .arg(gst_element_state_get_name(new_st));
                post_to_qt(call, [call, s]() { emit call->log(s); });
            }
            break;
        }
        case GST_MESSAGE_LATENCY:
            // Quiet — fired on every join.
            break;
        case GST_MESSAGE_ELEMENT: {
            // webrtcbin posts custom messages here — surface their structure
            // names so we can tell what's flowing internally even if no
            // notify signal fires.
            const GstStructure* s = gst_message_get_structure(msg);
            const gchar* sname = s ? gst_structure_get_name(s) : nullptr;
            if (sname) {
                QString line = QString("gst element-msg: %1").arg(sname);
                post_to_qt(call, [call, line]() { emit call->log(line); });
            }
            break;
        }
        default: break;
    }
    return TRUE;
}

}  // namespace

// ----------------- Public lifecycle -----------------------------------------

void MediaCall::start_outgoing(const std::array<std::uint8_t, 32>& peer_pub,
                                bool with_video) {
    if (state_ != State::kIdle) return;
    peer_pub_  = peer_pub;
    with_video_ = with_video;
    is_caller_ = true;

    QString err;
    impl_->pipeline = build_pipeline(with_video, &impl_->webrtc, &err);
    if (!impl_->pipeline) {
        emit log(err);
        set_state(State::kClosed);
        return;
    }
    // (Stale workaround removed: g_object_set_data on `this` is invalid —
    // this is a QObject not a GObject. Lambdas now retrieve webrtc via
    // MediaCall::_webrtc_raw().)
    g_signal_connect(impl_->webrtc, "on-negotiation-needed",
                     G_CALLBACK(on_negotiation_needed), this);
    g_signal_connect(impl_->webrtc, "on-ice-candidate",
                     G_CALLBACK(on_ice_candidate), this);
    g_signal_connect(impl_->webrtc, "pad-added",
                     G_CALLBACK(on_pad_added), this);
    g_signal_connect(impl_->webrtc, "notify::connection-state",
                     G_CALLBACK(on_connection_state_changed), this);
    g_signal_connect(impl_->webrtc, "notify::ice-gathering-state",
                     G_CALLBACK(on_ice_gathering_state_changed), this);
    g_signal_connect(impl_->webrtc, "notify::ice-connection-state",
                     G_CALLBACK(on_ice_connection_state_changed), this);
    g_signal_connect(impl_->webrtc, "notify::signaling-state",
                     G_CALLBACK(on_signaling_state_changed), this);

    impl_->bus       = gst_element_get_bus(impl_->pipeline);
    impl_->bus_watch = gst_bus_add_watch(impl_->bus, on_bus_message, this);

    set_state(State::kRinging);
    gst_element_set_state(impl_->pipeline, GST_STATE_PLAYING);
    if (sframe_enabled_) install_sframe_send_probes(impl_->pipeline, &impl_->sframe_ctx);   /* friend access via member fn scope */
}

void MediaCall::accept_incoming(bool with_video) {
    if (state_ != State::kRinging || is_caller_) return;
    with_video_ = with_video;
    emit log(QString("accept_incoming(video=%1) — building callee pipeline")
                 .arg(with_video ? "yes" : "no"));

    QString err;
    impl_->pipeline = build_pipeline(with_video, &impl_->webrtc, &err);
    if (!impl_->pipeline) {
        emit log(err);
        set_state(State::kClosed);
        return;
    }
    // (Stale workaround removed: see start_outgoing.)
    g_signal_connect(impl_->webrtc, "on-ice-candidate",
                     G_CALLBACK(on_ice_candidate), this);
    g_signal_connect(impl_->webrtc, "pad-added",
                     G_CALLBACK(on_pad_added), this);
    g_signal_connect(impl_->webrtc, "notify::connection-state",
                     G_CALLBACK(on_connection_state_changed), this);
    g_signal_connect(impl_->webrtc, "notify::ice-gathering-state",
                     G_CALLBACK(on_ice_gathering_state_changed), this);
    g_signal_connect(impl_->webrtc, "notify::ice-connection-state",
                     G_CALLBACK(on_ice_connection_state_changed), this);
    g_signal_connect(impl_->webrtc, "notify::signaling-state",
                     G_CALLBACK(on_signaling_state_changed), this);

    impl_->bus       = gst_element_get_bus(impl_->pipeline);
    impl_->bus_watch = gst_bus_add_watch(impl_->bus, on_bus_message, this);

    gst_element_set_state(impl_->pipeline, GST_STATE_PLAYING);
    if (sframe_enabled_) install_sframe_send_probes(impl_->pipeline, &impl_->sframe_ctx);   /* friend access via member fn scope */

    // Apply the buffered offer + create answer.
    GstSDPMessage* sdp_msg = nullptr;
    if (gst_sdp_message_new_from_text(pending_offer_.constData(), &sdp_msg) != GST_SDP_OK) {
        emit log("could not parse OFFER SDP");
        set_state(State::kClosed);
        return;
    }
    GstWebRTCSessionDescription* offer = gst_webrtc_session_description_new(
        GST_WEBRTC_SDP_TYPE_OFFER, sdp_msg);
    GstPromise* p = gst_promise_new();
    g_signal_emit_by_name(impl_->webrtc, "set-remote-description", offer, p);
    gst_promise_interrupt(p);
    gst_promise_unref(p);
    gst_webrtc_session_description_free(offer);

    // Drain any buffered ICE.
    for (const QByteArray& cand_json : pending_ice_) {
        receive_ice(cand_json);
    }
    pending_ice_.clear();

    // Create answer.
    GstPromise* ans_p = gst_promise_new_with_change_func(
        [](GstPromise* prom, gpointer u) {
            auto* self = static_cast<MediaCall*>(u);
            const GstStructure* reply = gst_promise_get_reply(prom);
            GstWebRTCSessionDescription* answer = nullptr;
            gst_structure_get(reply, "answer",
                              GST_TYPE_WEBRTC_SESSION_DESCRIPTION, &answer, nullptr);
            gst_promise_unref(prom);
            if (!answer) return;
            GstElement* webrtc = static_cast<GstElement*>(self->_webrtc_raw());
            GstPromise* sl = gst_promise_new();
            g_signal_emit_by_name(webrtc, "set-local-description", answer, sl);
            gst_promise_interrupt(sl);
            gst_promise_unref(sl);
            gchar* sdp_str = gst_sdp_message_as_text(answer->sdp);
            QByteArray sdp_bytes(sdp_str);
            g_free(sdp_str);
            gst_webrtc_session_description_free(answer);
            post_to_qt(self, [self, sdp_bytes]() {
                emit self->sendSignal(
                    static_cast<int>(MediaCall::SignalKind::kAnswer), sdp_bytes);
            });
        }, this, nullptr);
    g_signal_emit_by_name(impl_->webrtc, "create-answer", nullptr, ans_p);

    set_state(State::kConnecting);
}

void MediaCall::receive_offer(const QByteArray& sdp) {
    pending_offer_ = sdp;
    emit log(QString("OFFER received (%1 bytes); waiting for accept_incoming")
                 .arg(sdp.size()));
    set_state(State::kRinging);
}

void MediaCall::receive_answer(const QByteArray& sdp) {
    if (!impl_->webrtc) {
        emit log("ANSWER arrived but no pipeline yet — dropped");
        return;
    }
    emit log(QString("ANSWER received (%1 bytes); applying remote description")
                 .arg(sdp.size()));
    GstSDPMessage* sdp_msg = nullptr;
    if (gst_sdp_message_new_from_text(sdp.constData(), &sdp_msg) != GST_SDP_OK) {
        emit log("could not parse ANSWER SDP");
        return;
    }
    GstWebRTCSessionDescription* answer = gst_webrtc_session_description_new(
        GST_WEBRTC_SDP_TYPE_ANSWER, sdp_msg);
    GstPromise* p = gst_promise_new();
    g_signal_emit_by_name(impl_->webrtc, "set-remote-description", answer, p);
    gst_promise_interrupt(p);
    gst_promise_unref(p);
    gst_webrtc_session_description_free(answer);

    // Drain buffered ICE now that the remote description is set.
    if (!pending_ice_.empty()) {
        emit log(QString("draining %1 buffered ICE candidate(s)")
                     .arg(pending_ice_.size()));
    }
    for (const QByteArray& cand_json : pending_ice_) {
        receive_ice(cand_json);
    }
    pending_ice_.clear();

    set_state(State::kConnecting);
}

void MediaCall::receive_ice(const QByteArray& candidate_json) {
    if (!impl_->webrtc) {
        // Not yet built (callee hasn't accepted) — buffer.
        pending_ice_.push_back(candidate_json);
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(candidate_json);
    if (!doc.isObject()) return;
    QJsonObject obj = doc.object();
    QString cand = obj.value("candidate").toString();
    int mline    = obj.value("sdpMLineIndex").toInt();
    if (cand.isEmpty()) return;
    g_signal_emit_by_name(impl_->webrtc, "add-ice-candidate",
                          mline, cand.toUtf8().constData());
}

void MediaCall::set_self_muted(bool muted) {
    if (!impl_->pipeline) return;
    GstElement* vol = gst_bin_get_by_name(GST_BIN(impl_->pipeline), "mute_volume");
    if (!vol) return;
    g_object_set(vol, "mute", muted ? TRUE : FALSE, nullptr);
    gst_object_unref(vol);
    emit log(muted ? "outbound audio muted" : "outbound audio un-muted");
}

void MediaCall::hangup(bool silent) {
    if (state_ == State::kClosed) return;
    if (!silent) {
        emit sendSignal(static_cast<int>(SignalKind::kHangup), QByteArray());
    }
    if (impl_->bus_watch) { g_source_remove(impl_->bus_watch); impl_->bus_watch = 0; }
    if (impl_->bus)       { gst_object_unref(impl_->bus); impl_->bus = nullptr; }
    if (impl_->pipeline) {
        gst_element_set_state(impl_->pipeline, GST_STATE_NULL);
        gst_object_unref(impl_->pipeline);
        impl_->pipeline = nullptr;
        impl_->webrtc   = nullptr;
    }
    set_state(State::kClosed);
}

void MediaCall::set_state(State s) {
    if (state_ == s) return;
    state_ = s;
    emit stateChanged(s);
}

void* MediaCall::_webrtc_raw() const { return impl_->webrtc; }

void MediaCall::_on_connection_state(int gst_state) {
    // GstWebRTCPeerConnectionState: new=0, connecting=1, connected=2,
    // disconnected=3, failed=4, closed=5.
    if (state_ == State::kClosed) return;
    switch (gst_state) {
        case 2:                       // connected
            emit log("webrtc connection-state: connected");
            set_state(State::kLive);
            break;
        case 4:                       // failed
            emit log("webrtc connection-state: failed");
            hangup(/*silent=*/false);
            break;
        case 3:                       // disconnected — could recover; log only
            emit log("webrtc connection-state: disconnected");
            break;
        default: break;
    }
}

}  // namespace fb::desktop

#else  // FB_HAVE_GSTREAMER == 0

// Chat-only build (Windows desktop until GStreamer for MSVC is fully
// wired). Provide minimal stubs that match the .hpp signatures so the
// rest of the client links cleanly. Every method is a no-op except
// state inspection; calling start_outgoing / accept_incoming simply
// emits log() to surface the limitation to the user.

namespace fb::desktop {

struct MediaCall::Impl {};

MediaCall::MediaCall(QObject* parent)
    : QObject(parent), impl_(std::make_unique<Impl>()) {}
MediaCall::~MediaCall() = default;

void MediaCall::set_sframe_context(
    const std::array<std::uint8_t, 32>&,
    const std::array<std::uint8_t, 16>&) {}
void* MediaCall::_sframe_ctx_raw() { return nullptr; }
void* MediaCall::_webrtc_raw() const { return nullptr; }
void MediaCall::_on_connection_state(int) {}

void MediaCall::start_outgoing(
    const std::array<std::uint8_t, 32>& peer_pub, bool /*with_video*/) {
    peer_pub_ = peer_pub;
    emit log("voice / video disabled — this build is chat-only "
             "(GStreamer not available on this platform).");
    set_state(State::kClosed);
}

void MediaCall::accept_incoming(bool /*with_video*/) {
    emit log("voice / video disabled — this build is chat-only.");
    set_state(State::kClosed);
}

void MediaCall::receive_offer(const QByteArray& sdp) {
    pending_offer_ = sdp;
}
void MediaCall::receive_answer(const QByteArray&) {}
void MediaCall::receive_ice(const QByteArray&) {}

void MediaCall::set_self_muted(bool) {}
void MediaCall::hangup(bool /*silent*/) {
    set_state(State::kClosed);
}

void MediaCall::set_state(State s) {
    if (state_ == s) return;
    state_ = s;
    emit stateChanged(s);
}

void MediaCall::emit_local_ice(const QString&, const QString&, int) {}

}  // namespace fb::desktop

#endif  // FB_HAVE_GSTREAMER
