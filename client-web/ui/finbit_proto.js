// SPDX-License-Identifier: AGPL-3.0-or-later
// Hand-rolled protobuf wire-format encoder/decoder for the FinBit Frame
// vocabulary. Avoids pulling protobuf.js (200+ KB) for the seven message
// types we actually send/receive.
//
// Wire format (proto3 binary):
//   each field: tag (varint) | value
//   tag = (field_number << 3) | wire_type
//   wire_type: 0 = varint, 2 = length-delimited (bytes/string/embedded message)
//
// We only support what FinBit needs: varint, length-delimited, and the oneof
// pattern (each oneof variant is a different field number; the receiver
// dispatches on which tag fired).

'use strict';

// ---------- low-level varint + length-delimited ----------

export function encodeVarint(n) {
    const bytes = [];
    let v = BigInt(n);
    while (v >= 0x80n) {
        bytes.push(Number((v & 0x7fn) | 0x80n));
        v >>= 7n;
    }
    bytes.push(Number(v));
    return bytes;
}

export function decodeVarint(buf, off) {
    let v = 0n;
    let shift = 0n;
    while (true) {
        const b = buf[off++];
        v |= BigInt(b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7n;
    }
    return [v, off];
}

function writeTag(out, fieldNum, wireType) {
    for (const b of encodeVarint(fieldNum * 8 + wireType)) out.push(b);
}

function writeBytes(out, fieldNum, bytes) {
    if (!bytes) return;
    writeTag(out, fieldNum, 2);
    for (const b of encodeVarint(bytes.length)) out.push(b);
    for (const b of bytes) out.push(b);
}
function writeString(out, fieldNum, s) {
    if (!s) return;
    writeBytes(out, fieldNum, new TextEncoder().encode(s));
}
function writeUint32(out, fieldNum, n) {
    if (!n) return;  // proto3 default — skip
    writeTag(out, fieldNum, 0);
    for (const b of encodeVarint(n)) out.push(b);
}
function writeUint64(out, fieldNum, n) { writeUint32(out, fieldNum, n); }

// ---------- top-level Frame oneof field numbers ----------
// Mirrors core/proto/envelope.proto's Frame message:
const FRAME = {
    envelope: 1,
    batch: 2,
    control: 3,
    hello: 4,
    server_hello: 5,
    key_upload: 6,
    key_fetch: 7,
    key_fetch_resp: 8,
    register_req: 9,
    register_resp: 10,
    chan_subscribe: 11,
    chan_unsubscribe: 12,
    hello_ack: 13,
    username_lookup: 14,
    username_resp: 15,
};

// Wrap a serialized inner message as a top-level Frame.
function wrapFrame(fieldNum, innerBytes) {
    const out = [];
    writeBytes(out, fieldNum, innerBytes);
    return new Uint8Array(out);
}

// ---------- Frame builders ----------

export function encodeClientHello(identityPub, username, protoVersion = 1) {
    const inner = [];
    writeBytes(inner, 1, identityPub);
    writeString(inner, 2, username);
    writeUint32(inner, 3, protoVersion);
    return wrapFrame(FRAME.hello, new Uint8Array(inner));
}

export function encodeHelloAck(signature) {
    const inner = [];
    writeBytes(inner, 1, signature);
    return wrapFrame(FRAME.hello_ack, new Uint8Array(inner));
}

export function encodePreKeyBundle(identityPub, signedPrekey, publishedAtMs,
                                    pqPubkey = null, pqPubkeySig = null) {
    const inner = [];
    writeBytes(inner, 1, identityPub);
    writeBytes(inner, 2, signedPrekey);
    writeUint64(inner, 6, publishedAtMs);
    // Tier-7 PQ-hybrid fields. When the web client's PQ adapter is wired
    // up (see client-web/ui/finbit_pq.js) these are emitted; otherwise
    // they're absent and the wire is byte-identical to the pre-PQ form,
    // and peers fall back to pure X25519 for our envelopes.
    if (pqPubkey && pqPubkey.length > 0) {
        writeBytes(inner, 7, pqPubkey);
    }
    if (pqPubkeySig && pqPubkeySig.length > 0) {
        writeBytes(inner, 8, pqPubkeySig);
    }
    return new Uint8Array(inner);
}

export function encodeKeyBundleUpload(bundleBytes) {
    const inner = [];
    writeBytes(inner, 1, bundleBytes);
    return wrapFrame(FRAME.key_upload, new Uint8Array(inner));
}

// `requestId` is a u64 echoed by the server in the response so the caller
// can match concurrent fetches without relying on FIFO ordering. 0 means
// "no correlation requested" — the receiver falls back to oldest-first.
export function encodeKeyBundleFetch(username, requestId = 0) {
    const inner = [];
    writeString(inner, 1, username);
    writeUint64(inner, 2, requestId);
    return wrapFrame(FRAME.key_fetch, new Uint8Array(inner));
}

export function encodeUsernameLookup(pubkey) {
    const inner = [];
    writeBytes(inner, 1, pubkey);
    return wrapFrame(FRAME.username_lookup, new Uint8Array(inner));
}

// Envelope: recipient is a oneof — for DMs we use field 16 (user_pubkey).
export function encodeDmEnvelope({
    envelopeId, timestampMs, senderPubkey, recipientPubkey, ciphertext,
    aeadAlg = 1, protoVersion = 1, pqCt = null,
}) {
    const inner = [];
    writeBytes(inner, 1, envelopeId);
    writeUint64(inner, 2, timestampMs);
    writeBytes(inner, 3, senderPubkey);
    writeBytes(inner, 4, ciphertext);
    writeUint32(inner, 6, aeadAlg);
    writeUint32(inner, 7, protoVersion);
    // Tier-7 PQ-hybrid: 1088B ML-KEM-768 ciphertext when the web client's
    // PQ adapter is wired and the peer published a pq_pubkey. Empty
    // otherwise — the receiver falls back to pure X25519 derivation.
    if (pqCt && pqCt.length > 0) writeBytes(inner, 9, pqCt);
    writeBytes(inner, 16, recipientPubkey);  // user_pubkey (oneof recipient)
    return wrapFrame(FRAME.envelope, new Uint8Array(inner));
}

// DmPayload (inner-of-inner): oneof body { string text=1; ChannelKeyDistribution channel_key=2 }
//
// Note: writeString skips empty values (proto3 defaults aren't on the wire),
// but for a oneof variant we MUST emit the field tag even with an empty
// payload — otherwise the receiver sees no variant set and treats the DM as
// "unknown", silently dropping it.
export function encodeDmPayloadText(text) {
    const inner = [];
    const bytes = new TextEncoder().encode(text || "");
    writeTag(inner, 1, 2);
    for (const b of encodeVarint(bytes.length)) inner.push(b);
    for (const b of bytes) inner.push(b);
    return new Uint8Array(inner);
}

// DmPayload variant: ChannelKeyDistribution. `distribution` is the raw
// SenderKeysDistribution bytes returned by WebClient.create_channel_chain().
export function encodeDmPayloadChannelKey({ channelId, channelName, distribution }) {
    const ckd = [];
    writeBytes(ckd, 1, channelId);
    writeString(ckd, 2, channelName);
    writeBytes(ckd, 3, distribution);
    const inner = [];
    writeBytes(inner, 2, new Uint8Array(ckd));   // DmPayload.channel_key (field 2)
    return new Uint8Array(inner);
}

// MediaSignal kind constants — keep in sync with dm_payload.proto comments.
export const MEDIA_KIND = {
    OFFER:      1,
    ANSWER:     2,
    ICE:        3,
    HANGUP:     4,
    SFRAME_KEY: 5,
};

// DmPayload variant: MediaSignal — call signaling tunneled through the
// per-peer Double Ratchet so SDP / ICE / SFrame key never appear in cleartext
// to the relay or any TURN server.
export function encodeDmPayloadMediaSignal({ callId, kind, payload, epoch = 0 }) {
    const ms = [];
    writeBytes(ms, 1, callId);
    writeUint32(ms, 2, kind);
    writeBytes(ms, 3, payload);
    if (epoch) writeUint32(ms, 4, epoch);
    const inner = [];
    writeBytes(inner, 3, new Uint8Array(ms));   // DmPayload.media_signal (field 3)
    return new Uint8Array(inner);
}

// Channel-recipient Envelope — like encodeDmEnvelope but recipient is field
// 17 (channel_group_id) instead of 16 (user_pubkey).
export function encodeChannelEnvelope({
    envelopeId, timestampMs, senderPubkey, channelGroupId, ciphertext,
    aeadAlg = 1, protoVersion = 1,
}) {
    const inner = [];
    writeBytes(inner, 1, envelopeId);
    writeUint64(inner, 2, timestampMs);
    writeBytes(inner, 3, senderPubkey);
    writeBytes(inner, 4, ciphertext);
    writeUint32(inner, 6, aeadAlg);
    writeUint32(inner, 7, protoVersion);
    writeBytes(inner, 17, channelGroupId);  // channel_group_id (oneof recipient)
    return wrapFrame(FRAME.envelope, new Uint8Array(inner));
}

export function encodeChanSubscribe(channelId) {
    const inner = [];
    writeBytes(inner, 1, channelId);
    return wrapFrame(FRAME.chan_subscribe, new Uint8Array(inner));
}

export function encodeChanUnsubscribe(channelId) {
    const inner = [];
    writeBytes(inner, 1, channelId);
    return wrapFrame(FRAME.chan_unsubscribe, new Uint8Array(inner));
}

// ---------- Frame parser ----------
// Decodes a serialized Frame into { kind, fields } where fields is the
// decoded inner message. Only the body types we actually consume are
// supported.

function parseLD(buf, off) {
    const [len, after] = decodeVarint(buf, off);
    const n = Number(len);
    return [buf.subarray(after, after + n), after + n];
}

function parseFields(buf) {
    const fields = {};
    let off = 0;
    while (off < buf.length) {
        const [tag, afterTag] = decodeVarint(buf, off);
        const fnum = Number(tag) >> 3;
        const wt = Number(tag) & 7;
        if (wt === 0) {
            const [v, n] = decodeVarint(buf, afterTag);
            fields[fnum] = v;
            off = n;
        } else if (wt === 2) {
            const [bytes, n] = parseLD(buf, afterTag);
            fields[fnum] = bytes;
            off = n;
        } else {
            throw new Error(`unsupported wire type ${wt} for field ${fnum}`);
        }
    }
    return fields;
}

export function decodeFrame(buf) {
    if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
    const fields = parseFields(buf);
    const inverse = Object.fromEntries(
        Object.entries(FRAME).map(([k, v]) => [v, k]));
    for (const [fnum, value] of Object.entries(fields)) {
        const kind = inverse[fnum];
        if (!kind) continue;
        const inner = parseFields(value);
        return { kind, inner };
    }
    return { kind: "unknown", inner: fields };
}

// ---------- ServerHello field accessors (helper for app + tests) ----------
export function decodeServerHello(inner) {
    return {
        accepted: !!inner[1],
        detail: inner[2] ? new TextDecoder().decode(inner[2]) : "",
        serverRandom: inner[3] || new Uint8Array(),
    };
}

export function decodeKeyFetchResp(inner) {
    const found = !!inner[1];
    let bundle = null;
    if (inner[2]) {
        const b = parseFields(inner[2]);
        bundle = {
            identityPub: b[1] || new Uint8Array(),
            signedPrekey: b[2] || new Uint8Array(),
            // Tier-7 PQ-hybrid: peer's ML-KEM-768 pubkey + Ed25519
            // binding sig. Empty when peer is pre-PQ; web client falls
            // back to pure X25519 send (no harvest-now defense for this
            // envelope, but interop preserved).
            pqPubkey: b[7] || new Uint8Array(),
            pqPubkeySig: b[8] || new Uint8Array(),
        };
    }
    // `request_id` (u64) absent → 0n (legacy server fallback).
    const requestId = inner[3] ? BigInt(inner[3]) : 0n;
    return { found, bundle, requestId };
}

export function decodeEnvelope(inner) {
    return {
        envelopeId: inner[1] || new Uint8Array(),
        timestampMs: Number(inner[2] || 0n),
        senderPubkey: inner[3] || new Uint8Array(),
        ciphertext: inner[4] || new Uint8Array(),
        aeadAlg: Number(inner[6] || 0n),
        // Tier-7 PQ-hybrid: 1088B ML-KEM-768 ciphertext on the first
        // envelope of a hybrid session (chat_client / fb-cli ship this).
        // Web clients use it via the finbit_pq adapter when PQ is wired;
        // otherwise it's ignored (envelope still decrypts via X25519 if
        // the sender ALSO shipped the X25519 share — which they do).
        pqCt: inner[9] || new Uint8Array(),
        userPubkey: inner[16] || null,
        channelGroupId: inner[17] || null,
    };
}

export function decodeUsernameResp(inner) {
    return {
        pubkey: inner[1] || new Uint8Array(),
        username: inner[2] ? new TextDecoder().decode(inner[2]) : "",
        found: !!inner[3],
    };
}

export function decodeDmPayload(buf) {
    const fields = parseFields(buf);
    if (fields[1]) {
        return { kind: "text", text: new TextDecoder().decode(fields[1]) };
    }
    if (fields[2]) {
        const ckd = parseFields(fields[2]);
        return {
            kind: "channel_key",
            channelId:   ckd[1] || new Uint8Array(),
            channelName: ckd[2] ? new TextDecoder().decode(ckd[2]) : "",
            distribution: ckd[3] || new Uint8Array(),
        };
    }
    if (fields[3]) {
        const ms = parseFields(fields[3]);
        return {
            kind: "media_signal",
            callId:  ms[1] || new Uint8Array(),
            mediaKind: Number(ms[2] || 0n),
            payload: ms[3] || new Uint8Array(),
            epoch:   Number(ms[4] || 0n),
        };
    }
    return { kind: "unknown" };
}
