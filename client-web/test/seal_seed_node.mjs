// SPDX-License-Identifier: AGPL-3.0-or-later
// Smoke test for seal_seed / open_seed.
//
// Uses crypto_pwhash MIN-tier parameters (opslimit=1, memlimit=8192) so the
// test is instant — production uses INTERACTIVE (~64 MiB / 0.5s).

import FinBitModule from "../build/finbit.mjs";
import assert from "node:assert/strict";

const M = await FinBitModule();

const PASSPHRASE      = "correct horse battery staple";
const WRONG_PASSPHRASE = "tr0ub4dor&3";
const seed = new Uint8Array(32);
crypto.getRandomValues(seed);

// Smoke uses the lowest tier the bounds check still accepts (INTERACTIVE)
// — anything weaker would be rejected by open_seed's downgrade defense.
const OPS = 2;                  // INTERACTIVE
const MEM = 64 * 1024 * 1024;

const blob = M.seal_seed_with_params(PASSPHRASE, seed, OPS, MEM);
// v2: 1 (version) + 16 (salt) + 8 (ops) + 8 (mem) + 24 (nonce) + 32 (pt) + 16 (tag)
assert.equal(blob.length, 1 + 16 + 8 + 8 + 24 + 32 + 16, "vault blob unexpected size");
assert.equal(blob[0], 2, "vault version byte should be 2");
console.log("OK seal: %d bytes (v2)", blob.length);

// Right passphrase opens.
const opened = M.open_seed(PASSPHRASE, blob);
assert.ok(opened, "open_seed returned null on correct passphrase");
assert.deepEqual(new Uint8Array(opened), seed);
console.log("OK open with correct passphrase");

// Wrong passphrase fails (returns null, NOT throws).
const bad = M.open_seed(WRONG_PASSPHRASE, blob);
assert.equal(bad, null, "open_seed must return null on wrong passphrase");
console.log("OK wrong-passphrase rejected");

// Tampered ciphertext fails.
const tamp = new Uint8Array(blob);
tamp[tamp.length - 1] ^= 0x01;
const t = M.open_seed(PASSPHRASE, tamp);
assert.equal(t, null, "open_seed must return null on tampered blob");
console.log("OK tamper rejected");

// Truncated blob fails.
const trunc = blob.slice(0, blob.length - 3);
const tr = M.open_seed(PASSPHRASE, trunc);
assert.equal(tr, null, "open_seed must return null on truncated blob");
console.log("OK truncated-blob rejected");

// Two seals of the same seed produce different blobs (fresh salt + nonce).
const blob2 = M.seal_seed_with_params(PASSPHRASE, seed, OPS, MEM);
assert.notDeepEqual(new Uint8Array(blob), new Uint8Array(blob2));
console.log("OK distinct seals → distinct blobs");

// Default seal_seed uses MODERATE tier (~256 MiB / ~3 ops). On WASM this
// costs ~4-5 seconds per open, which is the per-guess cost a brute-forcer
// would pay against a stolen vault.
console.log("running default MODERATE seal (slow)…");
const t0 = Date.now();
const blobI = M.seal_seed(PASSPHRASE, seed);
const ms_seal = Date.now() - t0;
const t1 = Date.now();
const openedI = M.open_seed(PASSPHRASE, blobI);
const ms_open = Date.now() - t1;
assert.ok(openedI);
assert.deepEqual(new Uint8Array(openedI), seed);
console.log("OK MODERATE round-trip (seal=%d ms open=%d ms)", ms_seal, ms_open);

console.log("PASS: seed seal/open smoke.");
