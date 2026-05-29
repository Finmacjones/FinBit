// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Verifies the web client's Tier-7 PQ wire surface:
//   * encode/decode round-trips PreKeyBundle.pq_pubkey/_sig and
//     Envelope.pq_ct cleanly, in both legacy (no PQ) and PQ shapes.
//   * the default adapter (no vendor file present) gracefully no-ops
//     so the wire is byte-compatible with pre-PQ peers.
//   * when the vendor file IS present, the hybrid round-trip Alice→Bob
//     produces the same shared secret on both sides.
//
// Does NOT re-test the actual ML-KEM-768 algorithm — that's the
// vendored noble library's job (it ships its own test vectors).

import assert from "node:assert/strict";
import { test } from "node:test";

import * as P from "../ui/finbit_proto.js";
import * as PQ from "../ui/finbit_pq.js";

const rand = (n) => {
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i++) a[i] = (i * 31 + 7) & 0xff;
    return a;
};

// ---- Wire-shape tests (always run) ----------------------------------------

test("encodePreKeyBundle: pq fields omitted when not supplied (pre-PQ wire)", () => {
    const bundle = P.encodePreKeyBundle(rand(32), rand(32), 0n);
    assert.ok(bundle.length > 0);
    assert.ok(bundle.length < 200, `bundle without PQ should be ~80B; got ${bundle.length}`);
});

test("encodePreKeyBundle: pq fields ride when supplied", () => {
    const bundle = P.encodePreKeyBundle(rand(32), rand(32), 0n,
                                         rand(1184), rand(64));
    assert.ok(bundle.length > 1200);
    assert.ok(bundle.length < 1400);
});

test("encodeDmEnvelope: pqCt omitted when null (pre-PQ wire)", () => {
    const env = P.encodeDmEnvelope({
        envelopeId: rand(16), timestampMs: 0, senderPubkey: rand(32),
        recipientPubkey: rand(32), ciphertext: rand(64),
    });
    assert.ok(env.length > 0);
    assert.ok(env.length < 200);
});

test("encodeDmEnvelope: pqCt rides when supplied", () => {
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

// ---- Adapter behavior tests ------------------------------------------------

test("combineX25519Mlkem768 returns ssX unchanged when ML-KEM half is empty", async () => {
    const ssX = rand(32);
    const out = await PQ.combineX25519Mlkem768(ssX, new Uint8Array(0));
    assert.deepEqual(Array.from(out), Array.from(ssX));
});

if (!PQ.pqEnabled()) {
    // ---- Default-adapter (vendor absent) ---------------------------------
    test("PQ adapter OFF: pqEnabled() === false (vendor not installed)", () => {
        assert.equal(PQ.pqEnabled(), false);
    });

    test("PQ adapter OFF: derivePqIdentity → empty bytes", async () => {
        const id = await PQ.derivePqIdentity(rand(32), async () => rand(64));
        assert.equal(id.pub.length, 0);
        assert.equal(id.sec.length, 0);
        assert.equal(id.pubkeySig.length, 0);
    });

    test("PQ adapter OFF: encapForPeer / decapWithOwn → empty bytes", () => {
        const enc = PQ.encapForPeer(rand(1184));
        assert.equal(enc.ct.length, 0);
        assert.equal(enc.ss.length, 0);
        assert.equal(PQ.decapWithOwn(rand(1088), rand(2400)).length, 0);
    });
} else {
    // ---- Vendored-adapter (vendor present): real round-trips -------------
    //
    // Skipped automatically when the vendor file is absent — exercised once
    // `client-web/ui/vendor/noble-mlkem.mjs` has been verified + committed.

    test("PQ vendored: keygen-from-seed is deterministic across runs", async () => {
        const seed = rand(32);
        const a = await PQ.derivePqIdentity(seed, async () => rand(64));
        const b = await PQ.derivePqIdentity(seed, async () => rand(64));
        assert.deepEqual(Array.from(a.pub), Array.from(b.pub));
        assert.deepEqual(Array.from(a.sec), Array.from(b.sec));
        assert.equal(a.pub.length, 1184);
        assert.equal(a.sec.length, 2400);
    });

    test("PQ vendored: encap/decap round-trips to the same shared secret", async () => {
        const bobSeed = rand(32);
        const bob = await PQ.derivePqIdentity(bobSeed, async () => rand(64));
        const { ct, ss } = PQ.encapForPeer(bob.pub);
        assert.equal(ct.length, 1088);
        assert.equal(ss.length, 32);
        const recovered = PQ.decapWithOwn(ct, bob.sec);
        assert.equal(recovered.length, 32);
        assert.deepEqual(Array.from(recovered), Array.from(ss));
    });

    test("PQ vendored: hybrid combiner is symmetric Alice↔Bob", async () => {
        // Alice and Bob both possess each other's pq_pubkey via the
        // PreKeyBundle exchange. They derive the same hybrid root from
        // (their X25519 ECDH, their respective ML-KEM halves).
        const ssX = rand(32);                              // shared X25519 ECDH
        const bob = await PQ.derivePqIdentity(rand(32), async () => rand(64));
        const { ct, ss } = PQ.encapForPeer(bob.pub);

        // Alice side: combine her X25519 ECDH with her encap shared secret.
        const aliceRoot = await PQ.combineX25519Mlkem768(ssX, ss);
        // Bob side: decap to recover the same ss, combine identically.
        const bobSs    = PQ.decapWithOwn(ct, bob.sec);
        const bobRoot  = await PQ.combineX25519Mlkem768(ssX, bobSs);
        assert.deepEqual(Array.from(aliceRoot), Array.from(bobRoot));
        assert.equal(aliceRoot.length, 32);
    });
}
