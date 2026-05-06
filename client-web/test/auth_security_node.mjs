// SPDX-License-Identifier: AGPL-3.0-or-later
// Server-side login attacks. Drives the FinBit WebSocket directly so the
// client-side helpers don't paper over malicious frame shapes.
//
// What we want to prove:
//
//   1. Wrong-key signature: claim alice's pubkey, sign challenge with
//      Mallory's private key. Server's crypto_sign_verify_detached must
//      reject (and close the connection).
//
//   2. Replayed signature: take a valid HelloAck signature from session A
//      and present it on a fresh connection's challenge. Server must reject
//      (the random per-session challenge defeats replay).
//
//   3. RegisterReq cross-binding: an authenticated user (mallory) sends
//      RegisterReq{username:"alice", identity_pubkey:<mallory_pub>}. Server
//      must NOT bind a username to a key the connection didn't authenticate
//      against. (Security review #1/#2 — currently EXPECTED TO FAIL until
//      fix.)
//
//   4. Repeated ClientHello on an authenticated connection: must not
//      silently re-arm or unbind. (Security review #8.)
//
//   5. HelloAck before ClientHello: must close.

import FinBitModule from "../build/finbit.mjs";
import * as P from "../ui/finbit_proto.js";

const URL = process.env.WS_URL || "ws://127.0.0.1:8766";
const NAME_A = "alice-sec-" + Math.random().toString(36).slice(2, 7);
const NAME_M = "mallory-sec-" + Math.random().toString(36).slice(2, 7);

const M = await FinBitModule();
const WS = globalThis.WebSocket;   // Node 22 has it natively.

let failures = 0;
function fail(label, msg) {
    console.error(`FAIL ${label}: ${msg}`);
    failures++;
}
function ok(label, msg) {
    console.log(`OK   ${label}: ${msg}`);
}

// Helpers ---------------------------------------------------------------

function newWS() {
    const ws = new WS(URL);
    ws.binaryType = "arraybuffer";
    const inbox = [];
    let resolveOpen, openError;
    const opened = new Promise((r, j) => { resolveOpen = r; openError = j; });
    ws.onopen  = () => resolveOpen();
    ws.onerror = (e) => openError(e);
    ws.onmessage = (ev) => inbox.push(new Uint8Array(ev.data));
    return { ws, inbox, opened };
}

async function recvFrame(state, timeoutMs = 1500) {
    const t0 = Date.now();
    while (state.inbox.length === 0) {
        if (Date.now() - t0 > timeoutMs) return null;
        await new Promise((r) => setTimeout(r, 25));
    }
    const buf = state.inbox.shift();
    return P.decodeFrame(buf);
}

function send(ws, bytes) {
    ws.send(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
}

// === 1. Wrong-key signature ============================================
{
    const alice    = new M.WebClient();
    const mallory  = new M.WebClient();
    const s = newWS();
    await s.opened;
    // Claim alice's pubkey but sign with mallory.
    send(s.ws, P.encodeClientHello(alice.identity_pubkey(), NAME_A));
    const sh = await recvFrame(s);
    if (!sh || sh.kind !== "server_hello") {
        fail("wrong-key sig", `expected server_hello, got ${sh?.kind}`);
    } else {
        const challenge = sh.inner[3] || new Uint8Array();
        const wrongSig  = mallory.sign(challenge);
        send(s.ws, P.encodeHelloAck(wrongSig));
        // Server should close. Wait for any reply or close, then probe with
        // a non-pre-auth frame; if we get an envelope routed back we lose.
        await new Promise((r) => setTimeout(r, 250));
        const closed = (s.ws.readyState === s.ws.CLOSED || s.ws.readyState === s.ws.CLOSING);
        if (!closed) {
            fail("wrong-key sig", `connection still open after bad signature (state=${s.ws.readyState})`);
        } else {
            ok("wrong-key sig", "server closed");
        }
    }
    s.ws.terminate?.() ?? s.ws.close();
    alice.delete(); mallory.delete();
}

// === 2. Replayed signature ============================================
{
    const alice = new M.WebClient();
    // Session A — capture a real HelloAck signature.
    const a = newWS();
    await a.opened;
    send(a.ws, P.encodeClientHello(alice.identity_pubkey(), NAME_A + "-2"));
    const shA = await recvFrame(a);
    const challengeA = shA.inner[3];
    const sigA = alice.sign(challengeA);
    send(a.ws, P.encodeHelloAck(sigA));
    await new Promise((r) => setTimeout(r, 200));
    a.ws.terminate?.() ?? a.ws.close();

    // Session B — replay sigA.
    const b = newWS();
    await b.opened;
    send(b.ws, P.encodeClientHello(alice.identity_pubkey(), NAME_A + "-2"));
    const shB = await recvFrame(b);
    if (!shB || !shB.inner[3]) {
        fail("replay sig", `no challenge in session B`);
    } else {
        send(b.ws, P.encodeHelloAck(sigA));   // wrong challenge!
        await new Promise((r) => setTimeout(r, 250));
        const closed = (b.ws.readyState === b.ws.CLOSED || b.ws.readyState === b.ws.CLOSING);
        if (!closed) {
            fail("replay sig", "connection still open after replayed signature");
        } else {
            ok("replay sig", "server closed (challenge was fresh)");
        }
    }
    b.ws.terminate?.() ?? b.ws.close();
    alice.delete();
}

// === 3. RegisterReq cross-binding =====================================
//
// Mallory authenticates with HER OWN identity, then sends RegisterReq
// claiming username NAME_A bound to mallory_pub. With the security review
// findings in mind we expect this to (currently) succeed — meaning
// register_user("NAME_A", mallory_pub) would happen even though NAME_A
// already exists. Because dir.register_user IS idempotent + first-write-
// wins, the actual attack is registering a username Mallory doesn't own.
//
// Test: register a fresh username via RegisterReq with mallory's
// auth-bound pub, then a separate connection comes along claiming the
// same name with a DIFFERENT pub via ClientHello. If the server is
// hardened (review #1), the RegisterReq path also enforces "claim must
// match bound pubkey" — the request is rejected.
//
// We can't easily distinguish "RegisterReq accepted but ignored" from
// "RegisterReq accepted and stored" without a side-channel. Use the
// directory side effect: try to fetch a key bundle for the just-claimed
// name and see if the server returns the bundle uploaded by mallory.
{
    // Mallory authenticates as HER OWN identity (proves she owns mallory_pub
    // via the challenge-response). She then attempts a RegisterReq whose
    // `claim.identity_pubkey` is ALICE'S pubkey. Without enforcement she'd
    // bind a username to a pubkey she doesn't control — recipients of
    // username_lookup / key_fetch for that name would then end up talking
    // to alice's identity (which mallory still can't decrypt for; the harm
    // is misattribution, name-squatting, and confusing third parties).
    function encodeRegisterReq(name, pub) {
        const claim = [];
        claim.push((1 << 3) | 2); // field 1, wire 2 (bytes — identity_pubkey)
        for (const b of P.encodeVarint(pub.length)) claim.push(b);
        for (const b of pub) claim.push(b);
        claim.push((2 << 3) | 2); // field 2, wire 2 (string — username)
        const nb = new TextEncoder().encode(name);
        for (const b of P.encodeVarint(nb.length)) claim.push(b);
        for (const b of nb) claim.push(b);
        const reg = [];
        reg.push((1 << 3) | 2);
        for (const b of P.encodeVarint(claim.length)) reg.push(b);
        for (const b of claim) reg.push(b);
        const frame = [];
        frame.push((9 << 3) | 2);
        for (const b of P.encodeVarint(reg.length)) frame.push(b);
        for (const b of reg) frame.push(b);
        return new Uint8Array(frame);
    }

    const mallory = new M.WebClient();
    const alice   = new M.WebClient();    // mallory does NOT have alice's privkey
    const SQUAT_NAME = "ali-" + Math.random().toString(36).slice(2, 7);
    const m = newWS();
    await m.opened;
    send(m.ws, P.encodeClientHello(mallory.identity_pubkey(), ""));
    const shM = await recvFrame(m);
    send(m.ws, P.encodeHelloAck(mallory.sign(shM.inner[3])));
    await new Promise((r) => setTimeout(r, 80));

    // The cross-bind attack: claim username for somebody ELSE'S pubkey.
    send(m.ws, encodeRegisterReq(SQUAT_NAME, alice.identity_pubkey()));
    await new Promise((r) => setTimeout(r, 250));
    let regResp = null;
    while (m.inbox.length) {
        const f = P.decodeFrame(m.inbox.shift());
        if (f.kind === "register_resp") regResp = f;
    }
    const accepted = regResp && !!regResp.inner[1];
    if (accepted) {
        fail("register cross-bind",
             `server accepted mallory's RegisterReq binding '${SQUAT_NAME}' to alice_pub`);
    } else {
        const detail = regResp?.inner[2]
            ? new TextDecoder().decode(regResp.inner[2])
            : "(no detail)";
        ok("register cross-bind", `server rejected — ${detail}`);
    }
    m.ws.terminate?.() ?? m.ws.close();
    mallory.delete(); alice.delete();
}

// === 4. Second ClientHello on an authenticated connection ==============
{
    const a = new M.WebClient();
    const b = new M.WebClient();
    const s = newWS();
    await s.opened;
    // Auth as A.
    send(s.ws, P.encodeClientHello(a.identity_pubkey(), NAME_A + "-rehello"));
    const shA = await recvFrame(s);
    send(s.ws, P.encodeHelloAck(a.sign(shA.inner[3])));
    await new Promise((r) => setTimeout(r, 150));
    // Now attempt to re-Hello with B's pubkey on the same connection.
    send(s.ws, P.encodeClientHello(b.identity_pubkey(), NAME_M + "-rehello"));
    // The server might (a) reply with a fresh ServerHello (re-arm), (b)
    // close, or (c) silently ignore. Acceptable behaviour: close OR ignore
    // (no second server_hello). Fail only if a fresh challenge comes back.
    await new Promise((r) => setTimeout(r, 250));
    let secondSH = null;
    while (s.inbox.length) {
        const f = P.decodeFrame(s.inbox.shift());
        if (f.kind === "server_hello") secondSH = f;
    }
    if (secondSH) {
        fail("re-hello", "server re-armed challenge on an authenticated connection (review #8)");
    } else {
        ok("re-hello", "server ignored / closed on second ClientHello");
    }
    s.ws.terminate?.() ?? s.ws.close();
    a.delete(); b.delete();
}

// === 5. HelloAck before ClientHello ====================================
{
    const a = new M.WebClient();
    const s = newWS();
    await s.opened;
    // Send a HelloAck immediately with a fake signature; no Hello first.
    const fake = new Uint8Array(64);   // wrong size on purpose (sigs are 64B but unsigned)
    send(s.ws, P.encodeHelloAck(fake));
    await new Promise((r) => setTimeout(r, 250));
    const closed = (s.ws.readyState === s.ws.CLOSED || s.ws.readyState === s.ws.CLOSING);
    if (!closed) {
        fail("ack-before-hello", "connection still open after pre-Hello HelloAck");
    } else {
        ok("ack-before-hello", "server closed");
    }
    s.ws.terminate?.() ?? s.ws.close();
    a.delete();
}

if (failures > 0) {
    console.error(`${failures} security check(s) FAILED`);
    process.exit(1);
}
console.log("PASS: auth security smoke.");
