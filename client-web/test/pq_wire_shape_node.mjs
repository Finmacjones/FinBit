// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Verifies that the web client's Tier-7 PQ wire surface (Item 3) round-trips
// cleanly through encode/decode, that the default PQ adapter falls back to
// pure X25519 (no PQ on the wire), and that backward-compat with pre-PQ
// bundles + envelopes is preserved.
//
// Does NOT test the actual ML-KEM crypto — that lives in core/tests/handshake/
// (PqKem / HybridKem). The web side is the wire shape + the adapter seam.

import assert from "node:assert/strict";
import { test } from "node:test";

import * as P from "../ui/finbit_proto.js";
import * as PQ from "../ui/finbit_pq.js";

const rand = (n) => {
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i++) a[i] = (i * 31 + 7) & 0xff;
    return a;
};

test("encodePreKeyBundle: pq fields omitted when not supplied (pre-PQ wire)", () => {
    const idPub  = rand(32);
    const spkPub = rand(32);
    const bundle = P.encodePreKeyBundle(idPub, spkPub, 0n);
    // No field 7 (pq_pubkey) or field 8 (pq_pubkey_sig) appears in the bytes.
    // We just assert the bundle is non-empty and contains the expected
    // X25519 prekey bytes — a deeper invariant is that the bytes are
    // byte-identical to the pre-PQ encoding for the same inputs.
    assert.ok(bundle.length > 0);
    assert.ok(bundle.length < 200, `bundle should be ~80B without PQ; got ${bundle.length}`);
});

test("encodePreKeyBundle: pq fields ride when supplied (post-PQ wire)", () => {
    const idPub  = rand(32);
    const spkPub = rand(32);
    const pqPub  = rand(1184);
    const pqSig  = rand(64);
    const bundle = P.encodePreKeyBundle(idPub, spkPub, 0n, pqPub, pqSig);
    // ~80B header + 1184B PQ pubkey + 64B sig + a handful of tag bytes.
    assert.ok(bundle.length > 1200);
    assert.ok(bundle.length < 1400);
});

test("encodeDmEnvelope: pqCt omitted when null (pre-PQ wire)", () => {
    const env = P.encodeDmEnvelope({
        envelopeId: rand(16), timestampMs: 0, senderPubkey: rand(32),
        recipientPubkey: rand(32), ciphertext: rand(64),
    });
    assert.ok(env.length > 0);
    assert.ok(env.length < 200, `envelope without pq_ct should be ~150B; got ${env.length}`);
});

test("encodeDmEnvelope: pqCt rides when supplied (post-PQ wire)", () => {
    const env = P.encodeDmEnvelope({
        envelopeId: rand(16), timestampMs: 0, senderPubkey: rand(32),
        recipientPubkey: rand(32), ciphertext: rand(64), pqCt: rand(1088),
    });
    assert.ok(env.length > 1200);
});

test("decodeEnvelope: surfaces pqCt when wire carries it", () => {
    const pqCt = rand(1088);
    const env  = P.encodeDmEnvelope({
        envelopeId: rand(16), timestampMs: 0, senderPubkey: rand(32),
        recipientPubkey: rand(32), ciphertext: rand(64), pqCt,
    });
    // Strip the outer frame header (encodeDmEnvelope wraps in a Frame).
    // The frame wrapping is `{ tag, length, inner }` — easier: encode +
    // re-decode through the Frame layer rather than reaching inside.
    const frame = P.decodeFrame(env);
    assert.equal(frame.kind, "envelope");
    const decoded = P.decodeEnvelope(frame.inner);
    assert.equal(decoded.pqCt.length, 1088);
    assert.deepEqual(Array.from(decoded.pqCt), Array.from(pqCt));
});

test("decodeEnvelope: empty pqCt on pre-PQ wire", () => {
    const env = P.encodeDmEnvelope({
        envelopeId: rand(16), timestampMs: 0, senderPubkey: rand(32),
        recipientPubkey: rand(32), ciphertext: rand(64),
    });
    const frame = P.decodeFrame(env);
    const decoded = P.decodeEnvelope(frame.inner);
    assert.equal(decoded.pqCt.length, 0);
});

test("default PQ adapter is OFF and returns empty bytes", () => {
    assert.equal(PQ.pqEnabled(), false);
    const id = PQ.derivePqIdentity(rand(32), () => rand(64));
    assert.equal(id.pub.length, 0);
    assert.equal(id.sec.length, 0);
    assert.equal(id.pubkeySig.length, 0);
    const enc = PQ.encapForPeer(rand(1184));
    assert.equal(enc.ct.length, 0);
    assert.equal(enc.ss.length, 0);
    assert.equal(PQ.decapWithOwn(rand(1088), rand(2400)).length, 0);
});

test("combineX25519Mlkem768 returns X25519 unchanged when ML-KEM half is empty", () => {
    const ssX = rand(32);
    const out = PQ.combineX25519Mlkem768(ssX, new Uint8Array(0));
    assert.deepEqual(Array.from(out), Array.from(ssX));
});
