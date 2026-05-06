// SPDX-License-Identifier: AGPL-3.0-or-later
// Node-side smoke test for the new WASM surface:
//   1. WebClient.from_seed() — round-trip a 32-byte seed (the identity-
//      persistence flow used by IndexedDB); fingerprint must match the
//      original WebClient that produced the seed.
//   2. SenderKeys group ops — alice generates a chain, hands the
//      distribution to bob over a side-channel, bob installs it, alice
//      encrypts a message, bob decrypts it byte-for-byte.
//
// Use:  cd client-web && node test/wasm_channel_node.mjs
// Pure WASM — no WebSocket / network involvement.

import FinBitModule from "../build/finbit.mjs";
import assert from "node:assert/strict";

const M = await FinBitModule();

// Wrap a WASM call so a CppException becomes a real Error with message.
function tryW(label, fn) {
    try { return fn(); }
    catch (e) {
        let msg = "(unknown)";
        if (typeof e === "number" || (e && typeof e.excPtr === "number")) {
            const ptr = (typeof e === "number") ? e : e.excPtr;
            if (M.getExceptionMessage) msg = M.getExceptionMessage(ptr).join(": ");
        } else if (e && e.message) msg = e.message;
        throw new Error(`${label}: ${msg}`);
    }
}

// ---------- 1. seed round-trip (IndexedDB persistence path) ----------
const a1 = new M.WebClient();
const seed = new Uint8Array(a1.identity_seed());
assert.equal(seed.length, 32, "identity_seed must be 32 bytes");
const fp1 = a1.fingerprint();

const a2 = M.WebClient.from_seed(seed);
const fp2 = a2.fingerprint();
assert.equal(fp2, fp1, `from_seed produced different fingerprint (${fp1} vs ${fp2})`);
console.log("OK seed round-trip:", fp1);

// Tampered seed must not produce the same fingerprint.
const bad = new Uint8Array(seed);
bad[0] ^= 0x01;
const a3 = M.WebClient.from_seed(bad);
assert.notEqual(a3.fingerprint(), fp1, "tampered seed must yield different identity");
console.log("OK tampered-seed-yields-different-identity");

// ---------- 2. SenderKeys end-to-end via WASM only ----------
const alice = a1;
const bob   = new M.WebClient();

// Alice's identity pubkey is what bob will key the chain on.
const aliceIdPub = alice.identity_pubkey();
// Bob's chain peer-id likewise.
const bobIdPub   = bob.identity_pubkey();

// Use a deterministic 32-byte channel id for the test.
const channelId = new Uint8Array(32);
channelId.set([0xc0, 0xc4, 0x4e, 0x10]);

// Alice creates her own send chain — returns the SenderKeysDistribution
// (proto bytes) bob needs to start decrypting alice's messages.
const distA = tryW("create_channel_chain alice", () => alice.create_channel_chain(channelId));
assert.ok(distA.length > 0, "create_channel_chain must return non-empty distribution");

// Bob installs alice's distribution against alice's identity pubkey.
tryW("install_peer_dist bob", () => bob.install_channel_peer_dist(channelId, aliceIdPub, distA));

// Alice encrypts; the inner format is a serialized SenderKeysMessage proto.
const plaintext = new TextEncoder().encode("hello channel from alice");
const ct = tryW("channel_encrypt alice", () => alice.channel_encrypt(channelId, plaintext));
assert.ok(ct.length > plaintext.length, "ciphertext should expand by chain header + tag");

// Bob decrypts using alice's identity as the sender id.
const rt = tryW("channel_decrypt bob", () => bob.channel_decrypt(channelId, aliceIdPub, ct));
assert.ok(rt !== null, "channel_decrypt returned null on valid ciphertext");
assert.deepEqual(new Uint8Array(rt), plaintext);
console.log("OK channel_encrypt/decrypt: \"" +
            new TextDecoder().decode(new Uint8Array(rt)) + "\"");

// Now bob creates HIS own chain too (two-way chat) — alice installs.
const distB = bob.create_channel_chain(channelId);
alice.install_channel_peer_dist(channelId, bobIdPub, distB);

const pt2 = new TextEncoder().encode("reply from bob");
const ct2 = bob.channel_encrypt(channelId, pt2);
const rt2 = alice.channel_decrypt(channelId, bobIdPub, ct2);
assert.ok(rt2 !== null);
assert.deepEqual(new Uint8Array(rt2), pt2);
console.log("OK two-way: \"" + new TextDecoder().decode(new Uint8Array(rt2)) + "\"");

// Tamper with the ciphertext — must fail to decrypt.
const tampered = new Uint8Array(ct);
tampered[tampered.length - 1] ^= 0x01;
const bad2 = bob.channel_decrypt(channelId, aliceIdPub, tampered);
assert.equal(bad2, null, "tampered channel ciphertext must fail to decrypt");
console.log("OK channel-tamper-reject");

// Wrong sender id — bob has no chain for some random pubkey, must return null.
const stranger = new Uint8Array(32);
stranger.set([0xff, 0xee]);
const bad3 = bob.channel_decrypt(channelId, stranger, ct);
assert.equal(bad3, null, "channel_decrypt against unknown sender must return null");
console.log("OK channel-unknown-sender-reject");

console.log("PASS: WASM channel + identity-persistence smoke.");
