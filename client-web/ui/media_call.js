// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-side 1:1 voice/video calls.
//
// Architecture:
//   * RTCPeerConnection in P2P mode (no SFU yet — that comes when we add
//     mediasoup/Janus for group calls). DTLS-SRTP gives us hop-by-hop
//     media confidentiality for free between the two peers.
//   * SFrame layered on TOP of DTLS-SRTP via Insertable Streams. Even
//     when an SFU lands later, the SFU sees only frame-level ciphertext.
//     For the P2P case SFrame is technically redundant but we keep it
//     on so the protocol stays uniform.
//   * Signaling tunneled through the existing Double Ratchet DM
//     (FinBitConnection.sendMediaSignal). SDP / ICE / SFrame base key
//     never appear in cleartext to the relay.
//   * Per-call SFrame base key derived from
//          HKDF(shared_secret, info = "FinBit-SFrame-call-v1" || call_id)
//     The shared_secret comes from the existing X3DH-style derivation; the
//     call_id is fresh per call so two calls between the same peers never
//     share an SFrame key.

'use strict';

import * as P from "./finbit_proto.js";

// STUN works for ~80% of NATs. Symmetric NATs (carrier, hotel WiFi,
// some corporate networks) need TURN — without it WebRTC silently fails
// to gather a working candidate pair and the call hangs in "connecting".
//
// The user supplies their own TURN server (we don't run one); they paste
// the credentials into Settings → "TURN server" which writes them into
// localStorage under FB_TURN_URL / FB_TURN_USER / FB_TURN_PASS. Format
// for FB_TURN_URL: a single line, comma-separated for multiple URLs:
//   turn:example.com:3478?transport=udp,turns:example.com:5349
function buildIceServers() {
    const list = [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
    ];
    try {
        const url  = localStorage.getItem("FB_TURN_URL");
        const user = localStorage.getItem("FB_TURN_USER") || "";
        const cred = localStorage.getItem("FB_TURN_PASS") || "";
        if (url) {
            list.push({
                urls: url.split(",").map((s) => s.trim()).filter(Boolean),
                username: user,
                credential: cred,
            });
        }
    } catch { /* localStorage may be disabled in private mode */ }
    return list;
}

// HKDF-SHA256(shared, info) → 32 bytes via WebCrypto.
async function hkdf32(sharedBytes, infoStr) {
    const baseKey = await crypto.subtle.importKey(
        "raw", sharedBytes, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: new TextEncoder().encode(infoStr),
        },
        baseKey, 256);
    return new Uint8Array(bits);
}

// One CallSession per peer. Lifecycle: idle → ringing → connecting → live → closed.
export class CallSession extends EventTarget {
    /**
     * @param {Object} args
     * @param {string} args.peerName       UI-friendly peer label (sidebar key)
     * @param {Uint8Array} args.peerPub    32-byte Ed25519 identity pubkey of peer
     * @param {Uint8Array} args.sharedSecret 32-byte X3DH shared secret with peer
     * @param {Function}   args.sendSignal async (signal:{kind,callId,payload,epoch}) => void
     */
    constructor({ peerName, peerPub, sharedSecret, sendSignal }) {
        super();
        this.peerName = peerName;
        this.peerPub = peerPub;
        this.sharedSecret = sharedSecret;
        this.sendSignal = sendSignal;
        this.callId = crypto.getRandomValues(new Uint8Array(16));
        this.role = null;             // "caller" | "callee"
        this.state = "idle";
        this.pc = null;
        this.localStream = null;
        this.remoteStream = new MediaStream();
        this.sframeBaseKey = null;
        this.sframeEpoch = 1;
        this.sendCounter = 0n;
        // ICE candidates received before pc / remoteDescription is ready.
        // Initialized here so the callee path (receiveIce → before user
        // accepts → before _buildPeerConnection) doesn't crash.
        this._pendingIce = [];
    }

    // ----- public lifecycle ------------------------------------------------

    // Start an outbound call. `withVideo` true → also requests camera.
    async startOutgoing({ withVideo = false } = {}) {
        this.role = "caller";
        await this._buildPeerConnection();
        await this._addLocalMedia({ withVideo });
        this.sframeBaseKey = await hkdf32(
            this.sharedSecret,
            "FinBit-SFrame-call-v1-" + bufToHex(this.callId));
        const offer = await this.pc.createOffer();
        await this.pc.setLocalDescription(offer);
        this._setState("ringing");
        await this.sendSignal({
            kind: P.MEDIA_KIND.OFFER,
            callId: this.callId,
            payload: new TextEncoder().encode(offer.sdp),
        });
    }

    // Accept an inbound call (we've already received its OFFER).
    async accept(offerSdp, { withVideo = false } = {}) {
        if (this.role !== "callee") throw new Error("accept on non-callee session");
        await this._buildPeerConnection();
        await this._addLocalMedia({ withVideo });
        this.sframeBaseKey = await hkdf32(
            this.sharedSecret,
            "FinBit-SFrame-call-v1-" + bufToHex(this.callId));
        await this.pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
        // Drain any ICE we buffered before setRemoteDescription completed.
        for (const c of this._pendingIce) {
            try { await this.pc.addIceCandidate(c); } catch (e) { console.warn("ice apply", e); }
        }
        this._pendingIce = [];
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        await this.sendSignal({
            kind: P.MEDIA_KIND.ANSWER,
            callId: this.callId,
            payload: new TextEncoder().encode(answer.sdp),
        });
        this._setState("connecting");
    }

    // Inbound OFFER ingestion (called by FinBitConnection when an OFFER
    // signal arrives). We DON'T accept media yet — we just record state and
    // bubble onIncoming so the UI can prompt the user.
    receiveOffer(offerSdp) {
        this.role = "callee";
        this.offerSdp = offerSdp;
        this._setState("ringing");
        this.dispatchEvent(new CustomEvent("incoming", {
            detail: { peerName: this.peerName, peerPub: this.peerPub, callId: this.callId },
        }));
    }

    // Caller side: handle the ANSWER from the callee.
    async receiveAnswer(answerSdp) {
        if (!this.pc) throw new Error("no pc to apply answer to");
        await this.pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
        for (const c of this._pendingIce) {
            try { await this.pc.addIceCandidate(c); } catch (e) { console.warn("ice apply", e); }
        }
        this._pendingIce = [];
        this._setState("connecting");
    }

    // Trickle ICE candidate from the peer.
    async receiveIce(jsonStr) {
        let cand;
        try { cand = JSON.parse(jsonStr); } catch { return; }
        if (!this.pc || !this.pc.remoteDescription) {
            this._pendingIce.push(cand);
            return;
        }
        try { await this.pc.addIceCandidate(cand); }
        catch (e) { console.warn("addIceCandidate:", e); }
    }

    // Hang up locally. Sends HANGUP to peer if we haven't already.
    async hangup({ silent = false } = {}) {
        if (this.state === "closed") return;
        if (!silent) {
            try {
                await this.sendSignal({
                    kind: P.MEDIA_KIND.HANGUP,
                    callId: this.callId,
                    payload: new Uint8Array(0),
                });
            } catch { /* peer might already be gone */ }
        }
        this._teardown();
    }

    // ----- internals --------------------------------------------------------

    async _buildPeerConnection() {
        // NOTE: do NOT reset _pendingIce here — the callee may have buffered
        // candidates between OFFER arrival and user acceptance.
        this.pc = new RTCPeerConnection({
            iceServers: buildIceServers(),
            // Required for Insertable Streams on Chromium-based browsers.
            encodedInsertableStreams: true,
        });
        this.pc.onicecandidate = (ev) => {
            if (!ev.candidate) return;
            const json = JSON.stringify({
                candidate: ev.candidate.candidate,
                sdpMid: ev.candidate.sdpMid,
                sdpMLineIndex: ev.candidate.sdpMLineIndex,
            });
            this.sendSignal({
                kind: P.MEDIA_KIND.ICE,
                callId: this.callId,
                payload: new TextEncoder().encode(json),
            }).catch((e) => console.warn("ice signal send:", e));
        };
        this.pc.onconnectionstatechange = () => {
            const s = this.pc.connectionState;
            if (s === "connected") this._setState("live");
            if (s === "failed" || s === "disconnected" || s === "closed") {
                this._teardown();
            }
        };
        this.pc.ontrack = (ev) => {
            // Apply SFrame decrypt transform to the RECEIVER side.
            this._installRecvTransform(ev.receiver);
            this.remoteStream.addTrack(ev.track);
            this.dispatchEvent(new CustomEvent("track", {
                detail: { kind: ev.track.kind, stream: this.remoteStream },
            }));
        };
    }

    async _addLocalMedia({ withVideo }) {
        const constraints = { audio: true, video: !!withVideo };
        this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
        for (const track of this.localStream.getTracks()) {
            const sender = this.pc.addTrack(track, this.localStream);
            this._installSendTransform(sender);
        }
    }

    _installSendTransform(sender) {
        if (!sender.createEncodedStreams) {
            // Firefox uses the newer RTCRtpScriptTransform API (not yet
            // implemented here). Without either, only DTLS-SRTP protects
            // the media — adequate P2P, BUT NOT END-TO-END through an SFU.
            // Warn loudly so we never accidentally claim SFrame protection.
            this._sframeBypassed = true;
            console.warn("[FinBit] WARNING: SFrame disabled — browser lacks " +
                         "RTCRtpSender.createEncodedStreams (Insertable Streams). " +
                         "Media encryption falls back to DTLS-SRTP only.");
            return;
        }
        const { readable, writable } = sender.createEncodedStreams();
        const epoch = this.sframeEpoch;
        const baseKey = this.sframeBaseKey;
        const counterRef = { v: 0n };
        const ts = new TransformStream({
            transform: async (encodedFrame, controller) => {
                const sealed = await sframeSeal(baseKey, epoch, counterRef.v++,
                    new Uint8Array(encodedFrame.data));
                encodedFrame.data = sealed.buffer;
                controller.enqueue(encodedFrame);
            },
        });
        readable.pipeThrough(ts).pipeTo(writable).catch((e) => console.warn("send xform", e));
    }

    _installRecvTransform(receiver) {
        if (!receiver.createEncodedStreams) {
            this._sframeBypassed = true;
            console.warn("[FinBit] WARNING: SFrame disabled on receive — " +
                         "browser lacks createEncodedStreams. Inbound media " +
                         "is opened by DTLS-SRTP only.");
            return;
        }
        const { readable, writable } = receiver.createEncodedStreams();
        const baseKey = this.sframeBaseKey;
        const ts = new TransformStream({
            transform: async (encodedFrame, controller) => {
                const opened = await sframeOpen(baseKey, new Uint8Array(encodedFrame.data));
                if (!opened) return;   // tag mismatch / malformed → drop
                encodedFrame.data = opened.buffer;
                controller.enqueue(encodedFrame);
            },
        });
        readable.pipeThrough(ts).pipeTo(writable).catch((e) => console.warn("recv xform", e));
    }

    _teardown() {
        if (this.state === "closed") return;
        if (this.localStream) {
            for (const t of this.localStream.getTracks()) t.stop();
        }
        if (this.pc) {
            try { this.pc.close(); } catch {}
            this.pc = null;
        }
        this._setState("closed");
    }

    _setState(s) {
        this.state = s;
        this.dispatchEvent(new CustomEvent("statechange", { detail: { state: s } }));
    }
}

// =============================================================================
// SFrame (FinBit v1 — same wire format as core/include/fb/media/sframe.hpp).
// =============================================================================
//
// per_frame_key   = HKDF-SHA256(base_key, info = "FB-SFrame-key" || epoch||counter, L=32)
// per_frame_nonce = HKDF-SHA256(base_key, info = "FB-SFrame-nonce" || epoch||counter, L=12)
// ciphertext      = AES-256-GCM(plaintext, per_frame_key, per_frame_nonce,
//                               aad = epoch || counter)
// wire = [u32 BE epoch][u64 BE counter][ciphertext+tag]

const SFRAME_HEADER_BYTES = 4 + 8;

async function deriveFrameKey(baseKey, infoLabel, epoch, counter, lenBytes) {
    const info = new Uint8Array(infoLabel.length + 4 + 8);
    info.set(new TextEncoder().encode(infoLabel), 0);
    new DataView(info.buffer).setUint32(infoLabel.length, epoch >>> 0, false);
    new DataView(info.buffer).setBigUint64(infoLabel.length + 4, BigInt.asUintN(64, counter), false);
    const k = await crypto.subtle.importKey("raw", baseKey, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
        k, lenBytes * 8));
}

async function sframeSeal(baseKey, epoch, counter, plaintext) {
    const cBig = BigInt.asUintN(64, BigInt(counter));
    const fk = await deriveFrameKey(baseKey, "FB-SFrame-key",   epoch, cBig, 32);
    const nonce = await deriveFrameKey(baseKey, "FB-SFrame-nonce", epoch, cBig, 12);
    const aesKey = await crypto.subtle.importKey("raw", fk, "AES-GCM", false, ["encrypt"]);
    const aad = new Uint8Array(12);
    new DataView(aad.buffer).setUint32(0, epoch >>> 0, false);
    new DataView(aad.buffer).setBigUint64(4, cBig, false);
    const ctTag = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad }, aesKey, plaintext));
    const out = new Uint8Array(SFRAME_HEADER_BYTES + ctTag.length);
    out.set(aad, 0);
    out.set(ctTag, SFRAME_HEADER_BYTES);
    return out;
}

async function sframeOpen(baseKey, sealed) {
    if (sealed.length < SFRAME_HEADER_BYTES + 16) return null;
    const epoch   = new DataView(sealed.buffer, sealed.byteOffset).getUint32(0, false);
    const counter = new DataView(sealed.buffer, sealed.byteOffset).getBigUint64(4, false);
    const fk = await deriveFrameKey(baseKey, "FB-SFrame-key",   epoch, counter, 32);
    const nonce = await deriveFrameKey(baseKey, "FB-SFrame-nonce", epoch, counter, 12);
    const aesKey = await crypto.subtle.importKey("raw", fk, "AES-GCM", false, ["decrypt"]);
    const aad = sealed.subarray(0, SFRAME_HEADER_BYTES);
    const ctTag = sealed.subarray(SFRAME_HEADER_BYTES);
    try {
        const pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad }, aesKey, ctTag);
        return new Uint8Array(pt);
    } catch {
        return null;
    }
}

// Exposed for tests / interop checks.
export const _sframe = { sframeSeal, sframeOpen };

function bufToHex(b) {
    return [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
}
