// SPDX-License-Identifier: AGPL-3.0-or-later
// Smoke test for the call signaling layer: proto encoders and SFrame.
//
// What this DOESN'T test: the actual RTCPeerConnection / getUserMedia
// pipeline. That needs a real browser (no node-side polyfill exists for
// RTCRtpScriptTransform / encodedInsertableStreams). For end-to-end media
// we open the static UI in two browsers side by side.

import * as P from "../ui/finbit_proto.js";
import { _sframe } from "../ui/media_call.js";
import assert from "node:assert/strict";

// ---- 1. MediaSignal proto round-trip via DmPayload --------------------------
{
    const callId = new Uint8Array(16); callId[0] = 0xab;
    const sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
    const enc = P.encodeDmPayloadMediaSignal({
        callId,
        kind: P.MEDIA_KIND.OFFER,
        payload: new TextEncoder().encode(sdp),
    });
    const dec = P.decodeDmPayload(enc);
    assert.equal(dec.kind, "media_signal");
    assert.equal(dec.mediaKind, P.MEDIA_KIND.OFFER);
    assert.deepEqual(new Uint8Array(dec.callId), callId);
    assert.equal(new TextDecoder().decode(dec.payload), sdp);
    console.log("OK media-signal round-trip (OFFER, %d bytes)", enc.length);
}

// ---- 2. ICE / HANGUP / SFRAME_KEY variants ----------------------------------
{
    const cid = new Uint8Array(16); cid.set([1, 2, 3, 4]);
    for (const k of [P.MEDIA_KIND.ICE, P.MEDIA_KIND.HANGUP, P.MEDIA_KIND.ANSWER]) {
        const e = P.encodeDmPayloadMediaSignal({
            callId: cid, kind: k,
            payload: k === P.MEDIA_KIND.HANGUP ? new Uint8Array(0)
                                                : new TextEncoder().encode("payload"),
        });
        const d = P.decodeDmPayload(e);
        assert.equal(d.kind, "media_signal");
        assert.equal(d.mediaKind, k);
    }
    const sk = P.encodeDmPayloadMediaSignal({
        callId: cid, kind: P.MEDIA_KIND.SFRAME_KEY,
        payload: new Uint8Array(32).fill(0x42), epoch: 7,
    });
    const skDec = P.decodeDmPayload(sk);
    assert.equal(skDec.epoch, 7);
    assert.equal(skDec.payload.length, 32);
    console.log("OK media-signal variants (ICE/HANGUP/ANSWER/SFRAME_KEY)");
}

// ---- 3. SFrame seal/open round-trip -----------------------------------------
{
    const baseKey = crypto.getRandomValues(new Uint8Array(32));
    const epoch = 1;
    const counter = 0n;
    const frame = new TextEncoder().encode("encoded video frame bytes go here");
    const sealed = await _sframe.sframeSeal(baseKey, epoch, counter, frame);
    assert.ok(sealed.length === frame.length + 16 + 4 + 8,
              `sealed size unexpected: got ${sealed.length}, want ${frame.length + 28}`);
    const opened = await _sframe.sframeOpen(baseKey, sealed);
    assert.ok(opened);
    assert.deepEqual(opened, frame);
    console.log("OK SFrame round-trip (%d -> %d bytes sealed)", frame.length, sealed.length);

    // Tamper rejection.
    const bad = new Uint8Array(sealed);
    bad[bad.length - 1] ^= 0x01;
    const failed = await _sframe.sframeOpen(baseKey, bad);
    assert.equal(failed, null);
    console.log("OK SFrame tamper-rejected");

    // Wrong base key — must fail.
    const bk2 = crypto.getRandomValues(new Uint8Array(32));
    const failed2 = await _sframe.sframeOpen(bk2, sealed);
    assert.equal(failed2, null);
    console.log("OK SFrame wrong-key-rejected");

    // Multiple counters give distinct ciphertext for same plaintext.
    const a = await _sframe.sframeSeal(baseKey, epoch, 1n, frame);
    const b = await _sframe.sframeSeal(baseKey, epoch, 2n, frame);
    assert.notDeepEqual(new Uint8Array(a), new Uint8Array(b));
    console.log("OK SFrame distinct-counter-distinct-ciphertext");
}

console.log("PASS: media signaling + SFrame smoke.");
