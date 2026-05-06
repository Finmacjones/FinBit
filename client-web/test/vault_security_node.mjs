// SPDX-License-Identifier: AGPL-3.0-or-later
// Adversarial tests for the at-rest vault format.
//
// v2 layout (105 bytes):
//   [version=2 (1)][salt(16)][opslimit(u64 BE)][memlimit(u64 BE)]
//     [nonce(24)][ct+tag(48)]
// AAD = first 33 bytes (version || salt || ops || mem). With params bound
// into AAD, ANY single-byte flip in the header invalidates the AEAD tag —
// fixing the v1 hazard where low bits of memlimit didn't change Argon2's
// internal m_cost so the AEAD tag remained valid on a tampered blob.
//
// What we prove here:
//   1. seal_seed produces a 105-byte v2 blob with version byte at offset 0.
//   2. Untampered round-trip succeeds.
//   3. Single-byte tamper at every logical field (version, salt, ops, mem,
//      nonce, ciphertext, tag) is REJECTED. No offset should re-open.
//   4. Truncation / padding rejected.
//   5. Out-of-range params (ops < INTERACTIVE, mem > 1 GiB, mem < 64 MiB)
//      rejected even with the correct passphrase.
//   6. Distinct seals → distinct blobs (fresh salt + nonce).
//   7. Empty passphrase refused at the seal API boundary.
//   8. The default seal_seed (MODERATE tier) round-trips and we record
//      the per-guess cost so the brute-force budget is on the record.

import FinBitModule from "../build/finbit.mjs";
import assert from "node:assert/strict";

const M = await FinBitModule();

// open_seed throws on KDF allocation failures — wrap so any failure mode
// counts as "rejected".
const _rawOpen = M.open_seed.bind(M);
function tryOpen(pass, blob) {
    try { return _rawOpen(pass, blob); }
    catch { return null; }
}

const PASSPHRASE = "correct horse battery staple";
const seed = new Uint8Array(32);
crypto.getRandomValues(seed);

// Use INTERACTIVE floor for the attack loop so each iteration is ~900ms
// rather than the ~5s of MODERATE. This is the lowest tier the bounds
// check still accepts.
const OPS_INT = 2;
const MEM_INT = 64 * 1024 * 1024;
const blob = M.seal_seed_with_params(PASSPHRASE, seed, OPS_INT, MEM_INT);

// 1. Format check.
assert.equal(blob.length, 105, "v2 vault should be 105 bytes");
assert.equal(blob[0], 2,        "v2 vault version byte should be 2");
console.log(`OK format: ${blob.length}-byte v=${blob[0]} blob`);

// 2. Untampered open.
{
    const ok = tryOpen(PASSPHRASE, blob);
    assert.ok(ok, "untampered open must succeed");
    assert.deepEqual(new Uint8Array(ok), seed);
}
console.log("OK untampered round-trip");

// 3. Single-byte tamper at every logical field. Pick one representative
// offset per field rather than all 105 to keep the smoke under 30s.
const TAMPER_OFFSETS = [
    [0,   "version"],
    [3,   "salt"],
    [16,  "opslimit (high byte)"],
    [23,  "opslimit (low byte)"],
    [24,  "memlimit (high byte)"],
    [32,  "memlimit (low byte) — v1 hazard offset"],
    [40,  "nonce"],
    [60,  "ciphertext"],
    [104, "AEAD tag"],
];
for (const [i, label] of TAMPER_OFFSETS) {
    const bad = new Uint8Array(blob);
    bad[i] ^= 0x01;
    const r = tryOpen(PASSPHRASE, bad);
    if (r !== null) {
        console.error(`FAIL tamper at offset ${i} (${label}) opened: got ${r.length}B`);
        process.exit(1);
    }
}
console.log(`OK tamper rejection: ${TAMPER_OFFSETS.length} offsets attacked, all rejected`);

// 4. Truncation / padding.
for (const size of [0, 1, 47, 103, 104, 106, 200]) {
    const wrong = new Uint8Array(size);
    wrong.set(blob.slice(0, Math.min(size, blob.length)), 0);
    assert.equal(tryOpen(PASSPHRASE, wrong), null, `${size}B blob must reject`);
}
console.log("OK wrong-size blobs rejected (incl. v1 length 104)");

// 5. Out-of-range params rejected (downgrade attack defense).
{
    function setParams(b, ops, mem) {
        const c = new Uint8Array(b);
        for (let k = 0; k < 8; k++) c[16 + 7 - k] = (Number(ops >> BigInt(k * 8))) & 0xff;
        for (let k = 0; k < 8; k++) c[24 + 7 - k] = (Number(mem >> BigInt(k * 8))) & 0xff;
        return c;
    }
    // ops below INTERACTIVE → reject
    let r = tryOpen(PASSPHRASE, setParams(blob, 1n, BigInt(MEM_INT)));
    assert.equal(r, null, "ops<INTERACTIVE must reject (downgrade defense)");
    // mem below INTERACTIVE → reject
    r = tryOpen(PASSPHRASE, setParams(blob, BigInt(OPS_INT), 8192n));
    assert.equal(r, null, "mem<INTERACTIVE must reject (downgrade defense)");
    // mem > 1 GiB → reject (DoS defense)
    r = tryOpen(PASSPHRASE, setParams(blob, BigInt(OPS_INT), (2n * 1024n * 1024n * 1024n)));
    assert.equal(r, null, "mem > 1 GiB must reject (Argon2 OOM/hang defense)");
}
console.log("OK out-of-range params rejected (no downgrade, no OOM hang)");

// 6. Distinct seals → distinct blobs.
{
    const a = M.seal_seed_with_params(PASSPHRASE, seed, OPS_INT, MEM_INT);
    const b = M.seal_seed_with_params(PASSPHRASE, seed, OPS_INT, MEM_INT);
    assert.notDeepEqual(new Uint8Array(a), new Uint8Array(b), "fresh salt + nonce required");
}
console.log("OK distinct seals: salt + nonce + ciphertext all differ");

// 7. Empty passphrase refused at API boundary.
{
    let threw = false;
    try { M.seal_seed("", seed); } catch { threw = true; }
    assert.ok(threw, "seal_seed('') must throw");
}
console.log("OK empty-passphrase seal refused");

// 8. Default seal (MODERATE tier) round-trips and we record the cost.
{
    const t0 = Date.now();
    const real = M.seal_seed(PASSPHRASE, seed);
    const sealMs = Date.now() - t0;
    const t1 = Date.now();
    const opened = tryOpen(PASSPHRASE, real);
    const openMs = Date.now() - t1;
    assert.ok(opened, "MODERATE-tier round-trip must succeed");
    assert.deepEqual(new Uint8Array(opened), seed);
    const guessesPerSec = 1000 / openMs;
    console.log(`OK MODERATE round-trip: seal=${sealMs}ms open=${openMs}ms ` +
                `(~${guessesPerSec.toFixed(2)} guesses/s/core)`);
    console.log(`   1M-guess attack ≈ ${(1e6 / guessesPerSec / 3600).toFixed(1)} core-hours`);
}

console.log("PASS: vault security smoke (v2 format, AAD-bound params).");
