// SPDX-License-Identifier: AGPL-3.0-or-later
#include "room_forwarder.hpp"

#ifndef FB_HAVE_GSTREAMER
#  define FB_HAVE_GSTREAMER 1
#endif

#if FB_HAVE_GSTREAMER

#define GST_USE_UNSTABLE_API
#include <gst/gst.h>
#include <gst/sdp/sdp.h>
#include <gst/webrtc/webrtc.h>

#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>

#include "fb/media/forwarder.hpp"

namespace fb::desktop {

namespace {

constexpr const char* kStunUrl = "stun://stun.l.google.com:19302";

std::string key_of(const RoomForwarder::Pub& p) {
    return std::string(reinterpret_cast<const char*>(p.data()), p.size());
}
RoomForwarder::Pub pub_of(const std::string& k) {
    RoomForwarder::Pub p{};
    if (k.size() == p.size()) std::memcpy(p.data(), k.data(), p.size());
    return p;
}

// Run `fn` on the QObject's thread (GStreamer callbacks fire on glib/streaming
// threads; Qt signal emits must happen on the object's thread).
void post_to_qt(QObject* obj, std::function<void()> fn) {
    QMetaObject::invokeMethod(obj, std::move(fn), Qt::QueuedConnection);
}

QString turn_url_or_empty() {
    const char* e = std::getenv("FB_TURN_URL");
    return e ? QString::fromUtf8(e) : QString();
}

// A webrtcbin per leaf, configured like media_call's (max-bundle + STUN, plus
// any FB_TURN_URL). Borrowed pointer; owned by the pipeline once added.
GstElement* make_leaf_webrtc(const char* name) {
    GstElement* webrtc = gst_element_factory_make("webrtcbin", name);
    if (!webrtc) return nullptr;
    g_object_set(webrtc, "bundle-policy", GST_WEBRTC_BUNDLE_POLICY_MAX_BUNDLE,
                 "stun-server", kStunUrl, nullptr);
    const QString tu = turn_url_or_empty();
    if (!tu.isEmpty()) {
        gboolean ok = FALSE;
        g_signal_emit_by_name(webrtc, "add-turn-server",
                              tu.toUtf8().constData(), &ok);
    }
    return webrtc;
}

}  // namespace

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------
struct RoomForwarder::Impl {
    RoomForwarder*       owner = nullptr;
    RoomForwarder::Pub   room_id{};
    GstElement*          pipeline = nullptr;
    GstBus*              bus = nullptr;
    guint                bus_watch = 0;

    fb::media::ForwarderRouting routing;   // who relays to whom (pure)

    struct Leaf {
        RoomForwarder::Pub pub{};
        GstElement* webrtc   = nullptr;   // this leaf's PeerConnection
        GstElement* src_tee  = nullptr;   // tee fed by its depayloaded inbound
        bool        initial_done = false; // initial offer/answer settled
    };
    std::map<std::string, Leaf> leaves;   // key = raw pubkey bytes

    // One relay branch per directed edge: src's tee → {queue → rtpopuspay} →
    // sub's webrtcbin. Tracked so remove_leaf can tear the right ones down.
    struct Branch { GstElement* queue = nullptr; GstElement* pay = nullptr; };
    std::map<std::pair<std::string, std::string>, Branch> branches;

    // Per-signal callback context; owned here so it outlives the GObject
    // signal connections and is freed at shutdown.
    struct CbCtx { Impl* impl; std::string leaf; };
    std::vector<std::unique_ptr<CbCtx>> cbctxs;

    CbCtx* make_ctx(const std::string& leaf) {
        cbctxs.push_back(std::make_unique<CbCtx>(CbCtx{this, leaf}));
        return cbctxs.back().get();
    }

    Leaf* find(const std::string& k) {
        auto it = leaves.find(k);
        return it == leaves.end() ? nullptr : &it->second;
    }

    void wire_edge(const std::string& src, const std::string& sub);
    void tear_edge(const std::string& src, const std::string& sub);
};

namespace {

// Inbound pad of a leaf's webrtcbin (its mic) → jitterbuffer → depay → tee.
// NO DECODER: the depayloaded buffers are SFrame-sealed Opus the forwarder
// can't read, and that's exactly what we relay. Returns the tee, or null.
GstElement* build_recv_tee(GstElement* pipeline, GstPad* new_pad,
                           const std::string& leaf_key) {
    GstCaps* caps = gst_pad_get_current_caps(new_pad);
    if (!caps) caps = gst_pad_query_caps(new_pad, nullptr);
    if (!caps) return nullptr;
    GstStructure* s = gst_caps_get_structure(caps, 0);
    const gchar* enc = gst_structure_get_string(s, "encoding-name");
    const bool is_opus = enc && std::strcmp(enc, "OPUS") == 0;
    gst_caps_unref(caps);
    if (!is_opus) return nullptr;   // audio-only forwarder (Lever B / §4)

    GError* gerr = nullptr;
    // Re-payloading happens per-subscriber (rtpopuspay lives on each branch);
    // here we only depay to the sealed Opus frame and tee it.
    GstElement* chain = gst_parse_bin_from_description(
        "rtpjitterbuffer ! rtpopusdepay ! tee name=t allow-not-linked=true",
        TRUE, &gerr);
    if (!chain) { if (gerr) g_error_free(gerr); return nullptr; }
    g_object_set(chain, "message-forward", TRUE, nullptr);
    gst_bin_add(GST_BIN(pipeline), chain);
    gst_element_sync_state_with_parent(chain);

    GstPad* sink = gst_element_get_static_pad(chain, "sink");
    if (gst_pad_link(new_pad, sink) != GST_PAD_LINK_OK) {
        gst_object_unref(sink);
        return nullptr;
    }
    gst_object_unref(sink);
    // The tee is named "t" inside the bin; fetch it so callers can branch off.
    GstElement* tee = gst_bin_get_by_name(GST_BIN(chain), "t");
    (void)leaf_key;
    return tee;   // transfer: caller stores; unref handled at teardown
}

GstWebRTCSessionDescription* parse_desc(const QByteArray& sdp,
                                        GstWebRTCSDPType type) {
    GstSDPMessage* msg = nullptr;
    if (gst_sdp_message_new_from_text(sdp.constData(), &msg) != GST_SDP_OK)
        return nullptr;
    return gst_webrtc_session_description_new(type, msg);
}

}  // namespace

// Link src's tee → (queue → rtpopuspay) → sub's webrtcbin. Adding the send
// pad triggers webrtcbin renegotiation on `sub` (handled in
// on_fwd_negotiation_needed), which sends that leaf a fresh RoomOffer.
void RoomForwarder::Impl::wire_edge(const std::string& src,
                                    const std::string& sub) {
    if (src == sub) return;
    Leaf* ps = find(src);
    Leaf* pp = find(sub);
    if (!ps || !pp || !ps->src_tee || !pp->webrtc) return;   // not ready yet
    auto edge = std::make_pair(src, sub);
    if (branches.count(edge)) return;                        // already wired

    GstElement* queue = gst_element_factory_make("queue", nullptr);
    GstElement* pay   = gst_element_factory_make("rtpopuspay", nullptr);
    if (!queue || !pay) {
        if (queue) gst_object_unref(queue);
        if (pay) gst_object_unref(pay);
        return;
    }
    g_object_set(pay, "pt", 96, nullptr);
    gst_bin_add_many(GST_BIN(pipeline), queue, pay, nullptr);

    if (!gst_element_link_many(ps->src_tee, queue, pay, nullptr) ||
        !gst_element_link(pay, pp->webrtc)) {   // requests a sink pad on webrtc
        gst_element_set_state(queue, GST_STATE_NULL);
        gst_element_set_state(pay, GST_STATE_NULL);
        gst_bin_remove_many(GST_BIN(pipeline), queue, pay, nullptr);
        return;
    }
    gst_element_sync_state_with_parent(queue);
    gst_element_sync_state_with_parent(pay);
    branches[edge] = {queue, pay};

    // Tell ChatClient which member this new outbound section carries so it can
    // populate the subscriber's RoomOffer.track_bindings (§6A.3). The exact
    // SDP mid is finalised by the ensuing renegotiation; we surface a
    // best-effort id from the payloader and let the offer carry the canonical
    // mid. (Resolving the post-negotiation mid is part of the live wiring.)
    RoomForwarder* o = owner;
    RoomForwarder::Pub src_pub = pub_of(src), sub_pub = pub_of(sub);
    gchar* pay_name = gst_element_get_name(pay);
    QString mid = QString::fromUtf8(pay_name ? pay_name : "");
    g_free(pay_name);
    post_to_qt(o, [o, sub_pub, mid, src_pub]() {
        emit o->trackBinding(sub_pub, mid, src_pub);
    });
}

void RoomForwarder::Impl::tear_edge(const std::string& src,
                                    const std::string& sub) {
    auto it = branches.find({src, sub});
    if (it == branches.end()) return;
    Branch b = it->second;
    branches.erase(it);
    if (b.pay) {
        gst_element_set_state(b.pay, GST_STATE_NULL);
        gst_bin_remove(GST_BIN(pipeline), b.pay);
    }
    if (b.queue) {
        gst_element_set_state(b.queue, GST_STATE_NULL);
        gst_bin_remove(GST_BIN(pipeline), b.queue);
    }
}

namespace {

void on_fwd_pad_added(GstElement* /*webrtc*/, GstPad* new_pad, gpointer user) {
    auto* ctx = static_cast<RoomForwarder::Impl::CbCtx*>(user);
    auto* impl = ctx->impl;
    const std::string leaf = ctx->leaf;
    if (GST_PAD_DIRECTION(new_pad) != GST_PAD_SRC) return;

    GstElement* tee = build_recv_tee(impl->pipeline, new_pad, leaf);
    if (!tee) return;
    auto* L = impl->find(leaf);
    if (!L) { gst_object_unref(tee); return; }
    L->src_tee = tee;

    // Fan this newly-flowing source out to every current subscriber.
    for (const auto& sub : impl->routing.subscribers_of(leaf)) {
        impl->wire_edge(leaf, sub);
    }
    RoomForwarder* o = impl->owner;
    post_to_qt(o, [o]() { emit o->log("forwarder: inbound source teed + fanned"); });
}

void on_fwd_ice(GstElement* /*webrtc*/, guint mline, gchar* candidate,
                gpointer user) {
    auto* ctx = static_cast<RoomForwarder::Impl::CbCtx*>(user);
    RoomForwarder* o = ctx->impl->owner;
    RoomForwarder::Pub leaf = pub_of(ctx->leaf);
    QJsonObject obj;
    obj["candidate"] = QString::fromUtf8(candidate);
    obj["sdpMLineIndex"] = static_cast<int>(mline);
    QByteArray payload = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    post_to_qt(o, [o, leaf, payload]() { emit o->localIce(leaf, payload); });
}

// Adding outbound tracks to a leaf's webrtcbin makes it want to renegotiate:
// create an offer and send it as a RoomOffer; the leaf answers via
// leaf_answer(). Guarded so the INITIAL leaf→forwarder offer/answer (where
// the leaf is the offerer) isn't pre-empted.
void on_fwd_negotiation_needed(GstElement* webrtc, gpointer user) {
    auto* ctx = static_cast<RoomForwarder::Impl::CbCtx*>(user);
    auto* impl = ctx->impl;
    auto* L = impl->find(ctx->leaf);
    if (!L || !L->initial_done) return;   // initial answer flow owns the first round

    RoomForwarder* o = impl->owner;
    RoomForwarder::Pub leaf = pub_of(ctx->leaf);
    GstPromise* p = gst_promise_new_with_change_func(
        [](GstPromise* prom, gpointer u) {
            auto* c = static_cast<RoomForwarder::Impl::CbCtx*>(u);
            const GstStructure* reply = gst_promise_get_reply(prom);
            GstWebRTCSessionDescription* offer = nullptr;
            gst_structure_get(reply, "offer",
                              GST_TYPE_WEBRTC_SESSION_DESCRIPTION, &offer, nullptr);
            gst_promise_unref(prom);
            if (!offer) return;
            auto* L2 = c->impl->find(c->leaf);
            if (L2 && L2->webrtc) {
                GstPromise* sl = gst_promise_new();
                g_signal_emit_by_name(L2->webrtc, "set-local-description", offer, sl);
                gst_promise_interrupt(sl);
                gst_promise_unref(sl);
            }
            gchar* txt = gst_sdp_message_as_text(offer->sdp);
            QByteArray sdp(txt);
            g_free(txt);
            gst_webrtc_session_description_free(offer);
            RoomForwarder* oo = c->impl->owner;
            RoomForwarder::Pub lf = pub_of(c->leaf);
            post_to_qt(oo, [oo, lf, sdp]() { emit oo->renegotiateOffer(lf, sdp); });
        }, ctx, nullptr);
    g_signal_emit_by_name(webrtc, "create-offer", nullptr, p);
    (void)o; (void)leaf;
}

gboolean on_fwd_bus(GstBus*, GstMessage* msg, gpointer user) {
    auto* impl = static_cast<RoomForwarder::Impl*>(user);
    if (GST_MESSAGE_TYPE(msg) == GST_MESSAGE_ERROR) {
        GError* err = nullptr; gchar* dbg = nullptr;
        gst_message_parse_error(msg, &err, &dbg);
        QString s = QString("forwarder gst error: %1").arg(err ? err->message : "?");
        if (err) g_error_free(err);
        g_free(dbg);
        RoomForwarder* o = impl->owner;
        post_to_qt(o, [o, s]() { emit o->log(s); });
    }
    return TRUE;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------
RoomForwarder::RoomForwarder(const Pub& room_id, QObject* parent)
    : QObject(parent), impl_(std::make_unique<Impl>()) {
    impl_->owner = this;
    impl_->room_id = room_id;
    impl_->pipeline = gst_pipeline_new("room-forwarder");
    impl_->bus = gst_element_get_bus(impl_->pipeline);
    impl_->bus_watch = gst_bus_add_watch(impl_->bus, on_fwd_bus, impl_.get());
    gst_element_set_state(impl_->pipeline, GST_STATE_PLAYING);
}

RoomForwarder::~RoomForwarder() { shutdown(); }

void RoomForwarder::shutdown() {
    if (!impl_->pipeline) return;
    if (impl_->bus_watch) { g_source_remove(impl_->bus_watch); impl_->bus_watch = 0; }
    if (impl_->bus) { gst_object_unref(impl_->bus); impl_->bus = nullptr; }
    gst_element_set_state(impl_->pipeline, GST_STATE_NULL);
    gst_object_unref(impl_->pipeline);
    impl_->pipeline = nullptr;
    impl_->leaves.clear();
    impl_->branches.clear();
    impl_->cbctxs.clear();
}

void RoomForwarder::add_leaf(const Pub& leaf_pub, const QByteArray& offer_sdp) {
    const std::string key = key_of(leaf_pub);
    if (impl_->find(key)) return;   // already joined

    GstElement* webrtc = make_leaf_webrtc(nullptr);
    if (!webrtc) { emit log("forwarder: webrtcbin missing (gst-plugins-bad)"); return; }
    gst_bin_add(GST_BIN(impl_->pipeline), webrtc);

    Impl::Leaf leaf;
    leaf.pub = leaf_pub;
    leaf.webrtc = webrtc;
    impl_->leaves.emplace(key, leaf);

    Impl::CbCtx* ctx = impl_->make_ctx(key);
    g_signal_connect(webrtc, "pad-added", G_CALLBACK(on_fwd_pad_added), ctx);
    g_signal_connect(webrtc, "on-ice-candidate", G_CALLBACK(on_fwd_ice), ctx);
    g_signal_connect(webrtc, "on-negotiation-needed",
                     G_CALLBACK(on_fwd_negotiation_needed), ctx);
    gst_element_sync_state_with_parent(webrtc);

    // Apply the leaf's offer, then answer it.
    GstWebRTCSessionDescription* offer =
        parse_desc(offer_sdp, GST_WEBRTC_SDP_TYPE_OFFER);
    if (!offer) { emit log("forwarder: bad leaf offer SDP"); return; }
    GstPromise* rp = gst_promise_new();
    g_signal_emit_by_name(webrtc, "set-remote-description", offer, rp);
    gst_promise_interrupt(rp);
    gst_promise_unref(rp);
    gst_webrtc_session_description_free(offer);

    GstPromise* ap = gst_promise_new_with_change_func(
        [](GstPromise* prom, gpointer u) {
            auto* c = static_cast<Impl::CbCtx*>(u);
            const GstStructure* reply = gst_promise_get_reply(prom);
            GstWebRTCSessionDescription* answer = nullptr;
            gst_structure_get(reply, "answer",
                              GST_TYPE_WEBRTC_SESSION_DESCRIPTION, &answer, nullptr);
            gst_promise_unref(prom);
            if (!answer) return;
            auto* L = c->impl->find(c->leaf);
            if (L && L->webrtc) {
                GstPromise* sl = gst_promise_new();
                g_signal_emit_by_name(L->webrtc, "set-local-description", answer, sl);
                gst_promise_interrupt(sl);
                gst_promise_unref(sl);
                L->initial_done = true;   // renegotiation may proceed now
            }
            gchar* txt = gst_sdp_message_as_text(answer->sdp);
            QByteArray sdp(txt);
            g_free(txt);
            gst_webrtc_session_description_free(answer);
            RoomForwarder* o = c->impl->owner;
            RoomForwarder::Pub lf = pub_of(c->leaf);
            post_to_qt(o, [o, lf, sdp]() { emit o->answerReady(lf, sdp); });
        }, ctx, nullptr);
    g_signal_emit_by_name(webrtc, "create-answer", nullptr, ap);

    // Update the routing plan and fan EXISTING sources (those whose tee is
    // already flowing) into this newcomer. The reverse direction (this leaf's
    // own stream → others) is wired in on_fwd_pad_added once its tee appears.
    auto added = impl_->routing.add_leaf(key);
    for (const auto& e : added) {
        if (e.sub == key) impl_->wire_edge(e.src, e.sub);   // existing src → new leaf
    }
    emit log(QString("forwarder: leaf joined (%1 total)")
                 .arg(static_cast<int>(impl_->routing.leaf_count())));
}

void RoomForwarder::leaf_answer(const Pub& leaf_pub, const QByteArray& answer_sdp) {
    auto* L = impl_->find(key_of(leaf_pub));
    if (!L || !L->webrtc) return;
    GstWebRTCSessionDescription* answer =
        parse_desc(answer_sdp, GST_WEBRTC_SDP_TYPE_ANSWER);
    if (!answer) return;
    GstPromise* p = gst_promise_new();
    g_signal_emit_by_name(L->webrtc, "set-remote-description", answer, p);
    gst_promise_interrupt(p);
    gst_promise_unref(p);
    gst_webrtc_session_description_free(answer);
}

void RoomForwarder::leaf_ice(const Pub& leaf_pub, const QByteArray& candidate_json) {
    auto* L = impl_->find(key_of(leaf_pub));
    if (!L || !L->webrtc) return;
    QJsonDocument doc = QJsonDocument::fromJson(candidate_json);
    if (!doc.isObject()) return;
    QJsonObject obj = doc.object();
    QString cand = obj.value("candidate").toString();
    int mline = obj.value("sdpMLineIndex").toInt();
    if (cand.isEmpty()) return;
    g_signal_emit_by_name(L->webrtc, "add-ice-candidate", mline,
                          cand.toUtf8().constData());
}

void RoomForwarder::remove_leaf(const Pub& leaf_pub) {
    const std::string key = key_of(leaf_pub);
    auto* L = impl_->find(key);
    if (!L) return;

    // Tear down every relay branch touching this leaf (as source or sub).
    for (const auto& e : impl_->routing.remove_leaf(key)) {
        impl_->tear_edge(e.src, e.sub);
    }
    // Release the leaf's tee + webrtcbin.
    if (L->src_tee) {
        gst_element_set_state(L->src_tee, GST_STATE_NULL);
        // tee lives inside its parse-bin; removing the webrtc + bin below
        // takes the chain with it. Just drop our ref.
        gst_object_unref(L->src_tee);
    }
    if (L->webrtc) {
        gst_element_set_state(L->webrtc, GST_STATE_NULL);
        gst_bin_remove(GST_BIN(impl_->pipeline), L->webrtc);
    }
    impl_->leaves.erase(key);
    emit log(QString("forwarder: leaf left (%1 total)")
                 .arg(static_cast<int>(impl_->routing.leaf_count())));
}

std::size_t RoomForwarder::leaf_count() const {
    return impl_->routing.leaf_count();
}

}  // namespace fb::desktop

#else  // !FB_HAVE_GSTREAMER  — chat-only build: no media backend.

namespace fb::desktop {

struct RoomForwarder::Impl {};
RoomForwarder::RoomForwarder(const Pub&, QObject* parent)
    : QObject(parent), impl_(nullptr) {}
RoomForwarder::~RoomForwarder() = default;
void RoomForwarder::add_leaf(const Pub&, const QByteArray&) {}
void RoomForwarder::leaf_answer(const Pub&, const QByteArray&) {}
void RoomForwarder::leaf_ice(const Pub&, const QByteArray&) {}
void RoomForwarder::remove_leaf(const Pub&) {}
void RoomForwarder::shutdown() {}
std::size_t RoomForwarder::leaf_count() const { return 0; }

}  // namespace fb::desktop

#endif  // FB_HAVE_GSTREAMER
