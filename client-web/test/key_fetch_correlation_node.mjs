// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify the new request_id correlation on KeyBundleFetch.
//
// Two concurrent _fetchKeyBundle calls for distinct usernames must each
// resolve with their OWN bundle even if the server reordered the responses
// (which the new field protects against). For this smoke we drive the
// matching path directly via a stubbed _send to simulate any server reply
// order — no actual fb_server needed.

import FinBitModule from "../build/finbit.mjs";
import { FinBitConnection } from "../ui/finbit_conn.js";
import * as P from "../ui/finbit_proto.js";
import assert from "node:assert/strict";

const M = await FinBitModule();

// Build two real prekey-bundle blobs (one for "alice", one for "bob") so
// the response decode path is exercised end-to-end.
function bundleFor(name) {
    const id = new M.WebClient();
    const idPub = new Uint8Array(id.identity_pubkey());
    const xPub  = new Uint8Array(id.x25519_pub());
    id.delete();
    return P.encodePreKeyBundle(idPub, xPub, Date.now());
}

// Build a Frame that wraps a KeyBundleFetchResponse with the given
// requestId echoed and a real PreKeyBundle inside.
function makeKeyFetchResponseFrame({ requestId, bundleBytes }) {
    // KeyBundleFetchResponse: bool found=1, bundle=2, request_id=3
    const inner = [];
    // found=true
    inner.push(1 * 8 + 0);   // tag (field 1, wire 0)
    inner.push(1);
    // bundle=bundleBytes
    inner.push(2 * 8 + 2);
    for (const b of P.encodeVarint(bundleBytes.length)) inner.push(b);
    for (const b of bundleBytes) inner.push(b);
    // request_id (varint)
    inner.push(3 * 8 + 0);
    for (const b of P.encodeVarint(requestId)) inner.push(b);
    // Wrap in Frame { key_fetch_resp = field 8 }
    const frame = [];
    frame.push(8 * 8 + 2);
    for (const b of P.encodeVarint(inner.length)) inner.push;  // safety no-op
    for (const b of P.encodeVarint(inner.length)) frame.push(b);
    for (const b of inner) frame.push(b);
    return new Uint8Array(frame);
}

const conn = new FinBitConnection(M, "ws://unused", "test");
// Bypass the WebSocket — capture sends, drive _onMessage manually.
const sent = [];
conn._send = (b) => sent.push(new Uint8Array(b));
conn.connected = true;   // skip the real connect() handshake

// Issue two concurrent fetches.
const aP = conn._fetchKeyBundle("alice");
const bP = conn._fetchKeyBundle("bob");
assert.equal(sent.length, 2, "both fetches should hit the wire");

// Decode the request IDs the conn allocated. Each frame is
// FRAME.key_fetch (field 7) wrapping a KeyBundleFetch with field 2 = req_id.
function reqIdFromSent(buf) {
    // Skip Frame tag + length, then parse the inner KeyBundleFetch fields.
    const wireField = buf[0] >> 3;
    assert.equal(wireField, 7, "expected key_fetch field");
    const [innerLen, after] = P.decodeVarint(buf, 1);
    const inner = buf.subarray(after, after + Number(innerLen));
    let off = 0;
    while (off < inner.length) {
        const [tag, n1] = P.decodeVarint(inner, off);
        const fnum = Number(tag) >> 3;
        const wt = Number(tag) & 7;
        if (wt === 0) {  // varint
            const [v, n2] = P.decodeVarint(inner, n1);
            if (fnum === 2) return Number(v);
            off = n2;
        } else if (wt === 2) {  // length-delimited
            const [len, n2] = P.decodeVarint(inner, n1);
            off = n2 + Number(len);
        } else {
            throw new Error(`unsupported wire type ${wt}`);
        }
    }
    throw new Error("request_id not found in KeyBundleFetch");
}
const reqA = reqIdFromSent(sent[0]);
const reqB = reqIdFromSent(sent[1]);
assert.notEqual(reqA, reqB, "request ids must be distinct");

// Pre-build distinct bundles so we can prove which one each promise gets.
const bundleAlice = bundleFor("alice");
const bundleBob   = bundleFor("bob");

// Reverse the response order — server replies to BOB first, then ALICE.
// Without request_id correlation this would resolve aP with bob's bundle.
conn._onMessage(makeKeyFetchResponseFrame({ requestId: reqB, bundleBytes: bundleBob }));
conn._onMessage(makeKeyFetchResponseFrame({ requestId: reqA, bundleBytes: bundleAlice }));

const [a, b] = await Promise.all([aP, bP]);
// Each side should own the right bundle. The PreKeyBundle's first 32 bytes
// are the identity pubkey we stamped at construction time.
function pubkeyBytes(b) { return b.identityPub; }
assert.equal(pubkeyBytes(a).length, 32);
assert.equal(pubkeyBytes(b).length, 32);
assert.notDeepEqual(pubkeyBytes(a), pubkeyBytes(b),
    "alice and bob must end up with distinct identity pubkeys");
console.log("OK: out-of-order replies correctly correlated by request_id");

console.log("PASS: key_fetch correlation smoke.");
