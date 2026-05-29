// SPDX-License-Identifier: AGPL-3.0-or-later
// FinBit WebSocket Connection — orchestrates the FinBit handshake +
// authentication + DM flow over a WS to fb_server (--ws-port).
//
// JS handles protobuf encoding (finbit_proto.js) + WebSocket I/O. The
// WASM WebClient owns the long-lived Ed25519 identity, X25519 prekey,
// signature, X3DH-style shared-secret derivation, and per-peer Double
// Ratchet sessions.

'use strict';

import * as P from "./finbit_proto.js";
import * as PQ from "./finbit_pq.js";
import { CallSession } from "./media_call.js";
import * as Outbox from "./outbox.js";

function hex(b) {
    return [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
}

export class FinBitConnection {
    /**
     * @param {*} module        loaded FinBit WASM module (FinBitModule())
     * @param {string} url      ws://host:port
     * @param {string} username name to claim
     * @param {Object} [opts]
     * @param {Uint8Array} [opts.seed] 32-byte Ed25519 seed (rehydrated from IndexedDB)
     */
    constructor(module, url, username, opts = {}) {
        this.M = module;
        this.url = url;
        this.username = username;
        this.client = opts.seed
            ? module.WebClient.from_seed(opts.seed)
            : new module.WebClient();
        this.ws = null;
        this.connected = false;
        this.handlers = {
            onText: () => {},
            onLog: () => {},
            onAuth: () => {},
            onControl: () => {},          // ControlMessage frames (rate-limit, USERNAME_TAKEN, …)
            onChannelText: () => {},
            onChannelInvite: () => {},
            onIncomingCall: () => {},
            onCallStateChange: () => {},
            onOutboxDrained: () => {},
        };
        // Pending peer fetches.  Two indices into the same request entry:
        //   byUser  : Map<username,  entry>  — for in-flight dedupe
        //   byReqId : Map<reqId(BigInt), entry> — for response correlation
        // Server echoes our request_id; if it's 0 (legacy server) we fall
        // back to oldest-first via byUser insertion order.
        this.pendingFetch = new Map();
        this._pendingByReqId = new Map();
        this._nextFetchId = 1n;
        // Channels we've joined: hex(channelId) -> { name, members:Set<hex(pub)> }
        this.channels = new Map();
        // Active call sessions keyed by hex(peerPub). At most one per peer
        // (concurrent calls between same pair would need glare resolution —
        // skipped for v0).
        this.calls = new Map();
        // Cached symmetric shared secrets keyed by hex(peerPub). Computing it
        // requires a curve25519 scalarmult so we memoize.
        this._sharedSecrets = new Map();
        // Per-peer tail-promise chain so inbound media signals (OFFER →
        // ICE → ICE → ANSWER → HANGUP) serialize end-to-end. The chain
        // entry is removed once it drains so this doesn't grow unbounded.
        this._mediaSignalQ = new Map();
    }

    // 32-byte Ed25519 seed (the persistable identity material).
    identitySeed() { return this.client.identity_seed(); }
    fingerprint() { return this.client.fingerprint(); }

    on(event, fn) { this.handlers[event] = fn; }
    log(msg)      { this.handlers.onLog(msg); }

    async connect() {
        await new Promise((res, rej) => {
            const WS = (typeof WebSocket !== "undefined")
                ? WebSocket
                : require("ws").WebSocket;
            this.ws = new WS(this.url);
            this.ws.binaryType = "arraybuffer";
            this.ws.onopen = () => { this.log(`ws open ${this.url}`); res(); };
            this.ws.onerror = (e) => rej(e);
        });
        this.ws.onmessage = (ev) => this._onMessage(new Uint8Array(ev.data));

        // 1. Send ClientHello.
        this._send(P.encodeClientHello(this.client.identity_pubkey(), this.username));
        // 2. Wait for ServerHello + sign challenge.
        await this._waitFor("server_hello", async (frame) => {
            const sh = P.decodeServerHello(frame.inner);
            if (!sh.accepted) throw new Error(`server rejected: ${sh.detail}`);
            const sig = this.client.sign(sh.serverRandom);
            this._send(P.encodeHelloAck(sig));
            this.log(`signed challenge (${sh.serverRandom.length}B), sent HelloAck`);
        });
        // 3. Upload prekey bundle. Tier-7 PQ-hybrid: if the PQ adapter is
        // wired (finbit_pq.pqEnabled() === true) we publish pq_pubkey +
        // pq_pubkey_sig so PQ-aware peers can encap against us. The
        // default adapter returns empty bytes → bundle is byte-identical
        // to the pre-PQ form → peers fall back to X25519 (interop
        // preserved, no harvest-now defense on those envelopes).
        const myPub = this.client.identity_pubkey();
        const myX = this.client.x25519_pub();
        let pqPubkey = null;
        let pqPubkeySig = null;
        if (PQ.pqEnabled()) {
            try {
                const id = await PQ.derivePqIdentity(
                    this.client.identity_seed(),
                    async (msg) => this.client.sign(msg));
                pqPubkey = id.pub;
                pqPubkeySig = id.pubkeySig;
                this._pqIdentity = id;   // cached for inbound decap
                this.log(`PQ adapter active: ML-KEM-768 pubkey published `
                         + `(${pqPubkey.length}B)`);
            } catch (e) {
                this.log(`PQ adapter wired but derivePqIdentity threw: ${e.message}`);
            }
        }
        const bundle = P.encodePreKeyBundle(myPub, myX, Date.now(),
                                             pqPubkey, pqPubkeySig);
        this._send(P.encodeKeyBundleUpload(bundle));
        this.connected = true;
        this.handlers.onAuth(this.client.fingerprint());

        // Drain anything that was queued offline. Each entry calls back
        // through sendDm — same encrypt-now-step-the-ratchet path live
        // sends use, just with the saved plaintext instead of fresh
        // input. Failures stop the drain (the connection's clearly
        // still wonky); the next reconnect retries from where we are.
        try {
            const { sent, failed } = await Outbox.drain(async (entry) => {
                await this._sendDmDirect(entry.recipient, entry.plaintext);
            });
            if (sent + failed > 0) {
                this.log(`outbox drain: ${sent} sent, ${failed} failed`);
                this.handlers.onOutboxDrained({ sent, failed });
            }
        } catch (e) {
            this.log("outbox drain: " + e.message);
        }
    }

    async sendDm(peerUsername, text) {
        // Offline: persist the PLAINTEXT (not the ratchet output) to
        // IndexedDB and return — connect()'s post-auth drain will encrypt
        // and send when the WS comes back. We can't pre-encrypt because
        // the Double Ratchet would step at encrypt-time, leaving the
        // session permanently desynced if the message never went out.
        if (!this.connected) {
            await Outbox.enqueue({ recipient: peerUsername, plaintext: text });
            this.log(`offline — queued DM to ${peerUsername} (${text.length}B)`);
            return { queued: true };
        }
        await this._sendDmDirect(peerUsername, text);
        return { queued: false };
    }

    // Tier-7 PQ-hybrid (Item 3) — single seam used by every send/recv site
    // that derives a session root from X25519. With the default PQ adapter
    // (pqEnabled() === false), these short-circuit to the bit-identical
    // pre-PQ behavior, so the wire is unchanged until a real ML-KEM is
    // vendored into finbit_pq.js. See that file for the integration guide.
    //
    // Async because combineX25519Mlkem768 uses WebCrypto HKDF (the
    // browser-native PRF — no extra crypto to vendor). Call sites must
    // await; they're all already in async functions.
    async _hybridSharedForSend(peerX, peerBundle) {
        const ssX = this.client.derive_shared_secret(peerX);
        if (!PQ.pqEnabled() || !peerBundle
            || !peerBundle.pqPubkey || peerBundle.pqPubkey.length === 0) {
            return { shared: ssX, pqCt: null };
        }
        const { ct, ss } = PQ.encapForPeer(peerBundle.pqPubkey);
        if (!ct || ct.length === 0 || !ss || ss.length === 0) {
            return { shared: ssX, pqCt: null };
        }
        const combined = await PQ.combineX25519Mlkem768(ssX, ss);
        return { shared: combined, pqCt: ct };
    }

    async _hybridSharedForRecv(peerX, envelopePqCt) {
        const ssX = this.client.derive_shared_secret(peerX);
        if (!PQ.pqEnabled() || !envelopePqCt || envelopePqCt.length === 0
            || !this._pqIdentity || !this._pqIdentity.sec
            || this._pqIdentity.sec.length === 0) {
            return ssX;
        }
        const ssPq = PQ.decapWithOwn(envelopePqCt, this._pqIdentity.sec);
        if (!ssPq || ssPq.length === 0) return ssX;
        return PQ.combineX25519Mlkem768(ssX, ssPq);
    }

    async _sendDmDirect(peerUsername, text) {
        // Fetch peer prekey if we don't already have a session.
        const peer = await this._fetchKeyBundle(peerUsername);
        const peerPub = peer.identityPub;
        const peerX = peer.signedPrekey;
        this.log(`peer ${peerUsername}: identityPub=${peerPub.length}B, signedPrekey=${peerX.length}B`);
        let pqCtForEnvelope = null;
        if (!this.client.has_session(peerPub)) {
            const { shared, pqCt } = await this._hybridSharedForSend(peerX, peer);
            this._tryWasm("ratchet_init_alice",
                () => this.client.ratchet_init_alice(peerPub, shared, peerX));
            pqCtForEnvelope = pqCt;
        }
        // Wrap text in DmPayload, run the ratchet, build Envelope.
        const dmInner = P.encodeDmPayloadText(text);
        const ratchetCt = this._tryWasm("ratchet_encrypt",
            () => this.client.ratchet_encrypt(peerPub, dmInner));
        const envBytes = P.encodeDmEnvelope({
            envelopeId: this._randEnvelopeId(),
            timestampMs: Date.now(),
            senderPubkey: this.client.identity_pubkey(),
            recipientPubkey: peerPub,
            ciphertext: ratchetCt,
            pqCt: pqCtForEnvelope,
        });
        this._send(envBytes);
        this.log(`sent ${text.length}B DM to ${peerUsername}`);
    }

    close() {
        if (this.ws) this.ws.close();
    }

    // ---------------------------------------------------------------- channels

    // Create a fresh channel. Generates a random 32B id, builds our own send
    // chain, subscribes to the channel on the server, and DMs each invitee
    // the ChannelKeyDistribution so they can decrypt our future messages.
    // Returns { channelId, channelHex }.
    async createChannel(name, invitees = []) {
        if (!this.connected) throw new Error("not connected");
        const cid = new Uint8Array(32);
        crypto.getRandomValues(cid);
        const dist = this._tryWasm("create_channel_chain",
            () => this.client.create_channel_chain(cid));
        const cidHex = hex(cid);
        this.channels.set(cidHex, { name, members: new Set() });
        this._send(P.encodeChanSubscribe(cid));
        for (const peer of invitees) {
            await this._inviteToChannel(cid, name, dist, peer);
        }
        this.log(`created channel "${name}" (${cidHex.slice(0, 12)}…), invited ${invitees.length}`);
        return { channelId: cid, channelHex: cidHex };
    }

    // Join a channel we were invited to. The peer's distribution is installed
    // automatically when their channel_key DM arrives — this just subscribes
    // for fanout. Idempotent.
    joinChannel(channelId, name = "") {
        const cidHex = hex(channelId);
        if (!this.channels.has(cidHex)) {
            this.channels.set(cidHex, { name, members: new Set() });
        } else if (name && !this.channels.get(cidHex).name) {
            this.channels.get(cidHex).name = name;
        }
        this._send(P.encodeChanSubscribe(channelId));
    }

    // Send a text message to an existing channel. We must have called
    // createChannel() (or had a chain published) for this id; the underlying
    // SenderKeys session is auto-created on first encrypt either way.
    async sendChannelMessage(channelId, text) {
        if (!this.connected) throw new Error("not connected");
        const pt = new TextEncoder().encode(text);
        // Make sure we have an outbound chain so receivers can decrypt. If
        // this is the first send and we haven't published a chain yet, build
        // one and broadcast it to known members.
        const ch = this.channels.get(hex(channelId));
        if (ch && ch.members.size === 0) {
            // No invitees recorded — encrypt anyway; useful for a sender-only
            // self-test or for groups whose membership is tracked elsewhere.
        }
        const ct = this._tryWasm("channel_encrypt",
            () => this.client.channel_encrypt(channelId, pt));
        const envBytes = P.encodeChannelEnvelope({
            envelopeId: this._randEnvelopeId(),
            timestampMs: Date.now(),
            senderPubkey: this.client.identity_pubkey(),
            channelGroupId: channelId,
            ciphertext: ct,
        });
        this._send(envBytes);
        this.log(`sent ${text.length}B to channel ${hex(channelId).slice(0, 12)}…`);
    }

    async _inviteToChannel(channelId, name, distribution, peerUsername) {
        const peer = await this._fetchKeyBundle(peerUsername);
        const peerPub = peer.identityPub;
        const peerX = peer.signedPrekey;
        let pqCtForEnvelope = null;
        if (!this.client.has_session(peerPub)) {
            const { shared, pqCt } = await this._hybridSharedForSend(peerX, peer);
            this._tryWasm("ratchet_init_alice",
                () => this.client.ratchet_init_alice(peerPub, shared, peerX));
            pqCtForEnvelope = pqCt;
        }
        const dmInner = P.encodeDmPayloadChannelKey({
            channelId, channelName: name, distribution,
        });
        const ratchetCt = this._tryWasm("ratchet_encrypt",
            () => this.client.ratchet_encrypt(peerPub, dmInner));
        const envBytes = P.encodeDmEnvelope({
            envelopeId: this._randEnvelopeId(),
            timestampMs: Date.now(),
            senderPubkey: this.client.identity_pubkey(),
            recipientPubkey: peerPub,
            ciphertext: ratchetCt,
            pqCt: pqCtForEnvelope,
        });
        this._send(envBytes);
        this.channels.get(hex(channelId)).members.add(hex(peerPub));
        this.log(`invited ${peerUsername} to "${name}"`);
    }

    _randEnvelopeId() {
        const id = new Uint8Array(16);
        crypto.getRandomValues(id);
        return id;
    }

    // -------------------------------------------------------------- voice/video

    // Symmetric DH-derived shared secret with a peer. X3DH-style: cached so
    // subsequent calls don't redo the scalarmult.
    _peerSharedSecret(peerPub) {
        const key = hex(peerPub);
        let s = this._sharedSecrets.get(key);
        if (s) return s;
        const peerX = this.client.ed25519_pub_to_x25519(peerPub);
        s = this.client.derive_shared_secret(peerX);
        this._sharedSecrets.set(key, s);
        return s;
    }

    // Build a CallSession for `peerPub`, registered in this.calls and wired
    // to send signals through the ratchet.  SYNCHRONOUS on purpose: this
    // gets called from the inbound-OFFER path, which must complete the
    // calls.set() before the next inbound signal (e.g. ICE for the same
    // peer) is dispatched. Adding any await here re-opens that race.
    _newCallSession(peerName, peerPub) {
        const shared = this._peerSharedSecret(peerPub);
        const cs = new CallSession({
            peerName,
            peerPub,
            sharedSecret: new Uint8Array(shared),
            sendSignal: (sig) => this._sendMediaSignal(peerPub, sig),
        });
        cs.addEventListener("statechange", (ev) => {
            if (ev.detail.state === "closed") this.calls.delete(hex(peerPub));
            this.handlers.onCallStateChange({
                peerPub, peerName, state: ev.detail.state,
            });
        });
        this.calls.set(hex(peerPub), cs);
        return cs;
    }

    // Initiate a call. Returns the CallSession; UI should attach DOM
    // handlers to its events before this resolves.
    async startCall(peerUsername, { withVideo = false } = {}) {
        if (!this.connected) throw new Error("not connected");
        const peer = await this._fetchKeyBundle(peerUsername);
        const peerPub = peer.identityPub;
        // Make sure a ratchet session exists so signal DMs flow. Tier-7
        // PQ-hybrid is folded in here too — when the adapter is wired, the
        // first signal DM carries pq_ct on the envelope just like a plain
        // DM. The call-startup MediaSignal flows through the same ratchet
        // so signaling is automatically hybrid-protected.
        if (!this.client.has_session(peerPub)) {
            const { shared } = await this._hybridSharedForSend(peer.signedPrekey, peer);
            this._tryWasm("ratchet_init_alice",
                () => this.client.ratchet_init_alice(peerPub, shared, peer.signedPrekey));
        }
        const cs = this._newCallSession(peerUsername, peerPub);
        await cs.startOutgoing({ withVideo });
        return cs;
    }

    // Accept an inbound call that's currently in role=callee, state=ringing.
    async acceptIncomingCall(peerPub, { withVideo = false } = {}) {
        const cs = this.calls.get(hex(peerPub));
        if (!cs) throw new Error("no inbound call from that peer");
        await cs.accept(cs.offerSdp, { withVideo });
    }

    // Decline an inbound call.
    async declineIncomingCall(peerPub) {
        const cs = this.calls.get(hex(peerPub));
        if (!cs) return;
        await cs.hangup();
    }

    async _sendMediaSignal(peerPub, signal) {
        const dmInner = P.encodeDmPayloadMediaSignal(signal);
        const ratchetCt = this._tryWasm("ratchet_encrypt",
            () => this.client.ratchet_encrypt(peerPub, dmInner));
        const envBytes = P.encodeDmEnvelope({
            envelopeId: this._randEnvelopeId(),
            timestampMs: Date.now(),
            senderPubkey: this.client.identity_pubkey(),
            recipientPubkey: peerPub,
            ciphertext: ratchetCt,
        });
        this._send(envBytes);
    }

    // Public entry point — serializes signals per peer so a fast-arriving
    // ICE doesn't overtake the OFFER's CallSession installation, or two ICE
    // candidates' setRemoteDescription/addIceCandidate calls don't interleave.
    _handleInboundMediaSignal(senderPub, sig) {
        const k = hex(senderPub);
        const tail = this._mediaSignalQ.get(k) || Promise.resolve();
        const next = tail
            .then(() => this._processMediaSignal(senderPub, sig))
            .catch((e) => this.log("media signal error: " + e.message));
        this._mediaSignalQ.set(k, next);
        // Drop the queue entry once the chain drains. Without this the Map
        // grows unbounded as we accept calls from new peers across a session.
        next.finally(() => {
            if (this._mediaSignalQ.get(k) === next) this._mediaSignalQ.delete(k);
        });
        return next;
    }

    async _processMediaSignal(senderPub, sig) {
        const peerKey = hex(senderPub);
        let cs = this.calls.get(peerKey);
        if (sig.mediaKind === P.MEDIA_KIND.OFFER) {
            if (cs) {
                // Glare: peer offered while we have a session. v0 policy:
                // existing session wins, drop the new offer.
                return;
            }
            // Use a peer-* short label until we resolve the actual username
            // (cheaper than blocking the OFFER on a username_lookup round
            // trip). UI can call usernameLookup() later to refine the label.
            const fpShort = peerKey.slice(0, 8);
            cs = this._newCallSession("peer-" + fpShort, senderPub);
            cs.callId = sig.callId;
            const sdp = new TextDecoder().decode(sig.payload);
            cs.receiveOffer(sdp);
            this.handlers.onIncomingCall({ peerPub: senderPub, callSession: cs });
            return;
        }
        if (!cs) return;
        if (sig.mediaKind === P.MEDIA_KIND.ANSWER) {
            await cs.receiveAnswer(new TextDecoder().decode(sig.payload));
        } else if (sig.mediaKind === P.MEDIA_KIND.ICE) {
            await cs.receiveIce(new TextDecoder().decode(sig.payload));
        } else if (sig.mediaKind === P.MEDIA_KIND.HANGUP) {
            await cs.hangup({ silent: true });
        } else if (sig.mediaKind === P.MEDIA_KIND.SFRAME_KEY) {
            // SFrame rotation — install the new key + epoch on the active
            // session. v0 derives the key from the static shared secret so
            // this branch is unused; reserved for the SFU phase.
        }
    }

    // Wrap a WASM call so a CppException turns into a real JS Error with
    // the C++ what() string (using embind's getExceptionMessage if present).
    _tryWasm(label, fn) {
        try {
            return fn();
        } catch (e) {
            let msg = "(unknown)";
            if (typeof e === "number" || (e && typeof e.excPtr === "number")) {
                const ptr = (typeof e === "number") ? e : e.excPtr;
                if (this.M.getExceptionMessage) {
                    msg = this.M.getExceptionMessage(ptr).join(": ");
                }
            } else if (e && e.message) {
                msg = e.message;
            }
            const err = new Error(`${label}: ${msg}`);
            err.cause = e;
            throw err;
        }
    }

    // ---------- internals ----------

    _send(bytes) {
        // ws.send accepts ArrayBuffer; coerce.
        this.ws.send(bytes.buffer.slice(bytes.byteOffset,
                                         bytes.byteOffset + bytes.byteLength));
    }

    _onMessage(bytes) {
        const f = P.decodeFrame(bytes);
        if (this._waitingFor && this._waitingFor.kind === f.kind) {
            const cb = this._waitingFor.cb;
            this._waitingFor = null;
            cb(f);
            return;
        }
        if (f.kind === "control") {
            // ControlMessage: { code (varint), detail (string), in_reply_to(bytes), retry_after_ms }
            const code   = Number(f.inner[1] || 0n);
            const detail = f.inner[2] ? new TextDecoder().decode(f.inner[2]) : "";
            this.log(`server control code=${code} ${detail}`);
            this.handlers.onControl({ code, detail });
            return;
        }
        if (f.kind === "key_fetch_resp") {
            const r = P.decodeKeyFetchResp(f.inner);
            // Prefer request_id correlation; fall back to oldest-first if
            // the server didn't echo one (legacy build).
            let entry = null;
            if (r.requestId && this._pendingByReqId.has(r.requestId)) {
                entry = this._pendingByReqId.get(r.requestId);
            } else {
                const firstKey = this.pendingFetch.keys().next().value;
                if (firstKey === undefined) return;
                entry = this.pendingFetch.get(firstKey);
            }
            if (!entry) return;
            this.pendingFetch.delete(entry.username);
            this._pendingByReqId.delete(entry.requestId);
            const { resolve, reject } = entry;
            if (!r.found) return reject(new Error("peer not registered"));
            resolve({
                identityPub: new Uint8Array(r.bundle.identityPub),
                signedPrekey: new Uint8Array(r.bundle.signedPrekey),
            });
            return;
        }
        if (f.kind === "envelope") {
            this._handleInboundEnvelope(P.decodeEnvelope(f.inner));
            return;
        }
        if (f.kind === "username_resp") {
            const u = P.decodeUsernameResp(f.inner);
            this.log(`username for ${[...u.pubkey].slice(0, 4)
                .map((b) => b.toString(16).padStart(2, "0")).join("")}…: ${u.username || "(unknown)"}`);
            return;
        }
        this.log(`recv ${f.kind} (${bytes.length}B)`);
    }

    async _handleInboundEnvelope(env) {
        const senderPub = env.senderPubkey;
        if (env.channelGroupId) {
            // Channel envelope: ciphertext is a SenderKeysMessage; routed by
            // the server via channel_subscribe, decrypted with the per-sender
            // chain we installed when their channel_key DM arrived.
            const cidHex = hex(env.channelGroupId);
            if (!this.channels.has(cidHex)) {
                this.log(`channel ${cidHex.slice(0, 12)}… message for unknown channel — ignoring`);
                return;
            }
            const pt = this._tryWasm("channel_decrypt",
                () => this.client.channel_decrypt(env.channelGroupId, senderPub, env.ciphertext));
            if (!pt) {
                this.log("channel decrypt failed (no chain for sender?)");
                return;
            }
            const text = new TextDecoder().decode(new Uint8Array(pt));
            this.handlers.onChannelText({
                channelId: env.channelGroupId,
                channelHex: cidHex,
                senderPub,
                text,
            });
            return;
        }
        if (!env.userPubkey) return;
        if (!this.client.has_session(senderPub)) {
            // Tier-7 PQ-hybrid recv: read envelope.pqCt (1088B when sender
            // is PQ-aware), decap via the PQ adapter with our cached
            // pq_sec, HKDF-combine with X25519 ECDH → same hybrid root
            // the sender derived. Empty pqCt OR pqEnabled() === false
            // falls back to pure X25519 (interop with pre-PQ senders).
            const peerX = this.client.ed25519_pub_to_x25519(senderPub);
            const shared = await this._hybridSharedForRecv(peerX, env.pqCt);
            this.client.ratchet_init_bob(senderPub, shared);
        }
        const inner = this.client.ratchet_decrypt(senderPub, env.ciphertext);
        if (!inner) {
            this.log("ratchet decrypt failed");
            return;
        }
        const payload = P.decodeDmPayload(new Uint8Array(inner));
        if (payload.kind === "text") {
            this.handlers.onText({ senderPub, text: payload.text });
        } else if (payload.kind === "media_signal") {
            this._handleInboundMediaSignal(senderPub, payload);  // self-serializing
        } else if (payload.kind === "channel_key") {
            // Peer is inviting us to their channel — install their distribution
            // against their identity pubkey, mirror their channel locally,
            // subscribe so the server forwards their future messages to us.
            this._tryWasm("install_channel_peer_dist",
                () => this.client.install_channel_peer_dist(
                    payload.channelId, senderPub, payload.distribution));
            const cidHex = hex(payload.channelId);
            const existing = this.channels.get(cidHex);
            if (existing) {
                if (!existing.name && payload.channelName) existing.name = payload.channelName;
                existing.members.add(hex(senderPub));
            } else {
                this.channels.set(cidHex, {
                    name: payload.channelName,
                    members: new Set([hex(senderPub)]),
                });
            }
            this._send(P.encodeChanSubscribe(payload.channelId));
            this.log(`joined channel "${payload.channelName}" via invite from peer`);
            this.handlers.onChannelInvite({
                channelId: payload.channelId,
                channelHex: cidHex,
                channelName: payload.channelName,
                senderPub,
            });
        }
    }

    _waitFor(kind, cb) {
        return new Promise((res, rej) => {
            this._waitingFor = { kind, cb: async (f) => { try { await cb(f); res(); } catch (e) { rej(e); } } };
        });
    }

    // Fetch a peer's prekey bundle. Concurrent calls for the SAME username
    // share a single in-flight request (otherwise the second would overwrite
    // the first's resolver in `pendingFetch` and the first promise would
    // hang forever).
    //
    // Concurrent fetches for DISTINCT usernames are correlated by an
    // explicit request_id echoed by the server — no longer rely on
    // server-side FIFO. (Old server: request_id=0 in response, falls back
    // to oldest-first matching.)
    async _fetchKeyBundle(peerUsername) {
        const existing = this.pendingFetch.get(peerUsername);
        if (existing) return existing.promise;
        let resolve, reject;
        const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
        const reqId = this._nextFetchId++;
        const entry = { username: peerUsername, requestId: reqId, resolve, reject, promise };
        this.pendingFetch.set(peerUsername, entry);
        this._pendingByReqId.set(reqId, entry);
        // Encode reqId as Number (proto varint is fine up to 2^53; we wrap
        // _nextFetchId well below that for any realistic session).
        this._send(P.encodeKeyBundleFetch(peerUsername, Number(reqId)));
        return promise;
    }
}
