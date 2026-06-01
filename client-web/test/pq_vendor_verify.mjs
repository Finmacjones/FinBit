// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Vendor acceptance gate for the ML-KEM-768 bundle at
// client-web/ui/vendor/noble-mlkem.mjs (see ui/vendor/README.md).
//
// Run this AFTER dropping the vendored file in, BEFORE committing it. It is
// the "is this bundle the real, correct, FinBit-compatible ML-KEM-768?" check.
// It deliberately does NOT replace the upstream's own NIST/ACVP known-answer
// vectors (run those too — noble ships them); it asserts the properties
// FinBit's design actually depends on, plus a distinctive FIPS-203 behaviour
// (implicit rejection) that a stub or tampered bundle would not reproduce.
//
//   node client-web/test/pq_vendor_verify.mjs
//
// Skips cleanly (exit 0) when the vendor file is absent, so it's safe to wire
// into CI before anyone has vendored anything.

import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

const VENDOR_URL = new URL("../ui/vendor/noble-mlkem.mjs", import.meta.url);
const present = existsSync(fileURLToPath(VENDOR_URL));

// FIPS-203 ML-KEM-768 byte sizes — the contract finbit_pq.js relies on.
const SEED = 64, PUB = 1184, SEC = 2400, CT = 1088, SS = 32;

let ml_kem768 = null;
if (present) {
    const m = await import(VENDOR_URL.href);
    ml_kem768 = m.ml_kem768 || m.default?.ml_kem768 || null;
}

// A fixed, non-trivial 64-byte seed (deterministic so the test is repeatable;
// value itself is irrelevant — we only assert keygen is a pure function of it).
const seedA = Uint8Array.from({ length: SEED }, (_, i) => (i * 7 + 3) & 0xff);
const seedB = Uint8Array.from({ length: SEED }, (_, i) => (i * 11 + 5) & 0xff);

const eq = (a, b) =>
    a.length === b.length && a.every((x, i) => x === b[i]);

test("vendor file present", { skip: present ? false : "no vendor file — skipping" }, () => {
    assert.ok(ml_kem768, "vendor exports an ml_kem768 object");
    for (const fn of ["keygen", "encapsulate", "decapsulate"]) {
        assert.equal(typeof ml_kem768[fn], "function", `ml_kem768.${fn} is a function`);
    }
});

test("keygen sizes match FIPS-203 ML-KEM-768", { skip: present ? false : "no vendor file" }, () => {
    const { publicKey, secretKey } = ml_kem768.keygen(seedA);
    assert.equal(publicKey.length, PUB, `publicKey ${PUB}B`);
    assert.equal(secretKey.length, SEC, `secretKey ${SEC}B`);
});

test("encapsulate/decapsulate sizes + round-trip agree", { skip: present ? false : "no vendor file" }, () => {
    const { publicKey, secretKey } = ml_kem768.keygen(seedA);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    assert.equal(cipherText.length, CT, `cipherText ${CT}B`);
    assert.equal(sharedSecret.length, SS, `sharedSecret ${SS}B`);
    const recovered = ml_kem768.decapsulate(cipherText, secretKey);
    assert.ok(eq(recovered, sharedSecret), "decapsulated SS equals encapsulated SS");
});

// FinBit's hard requirement: the PQ keypair is derived deterministically from
// the identity seed (fb::handshake::derive_pq_identity). The library MUST make
// keygen a pure function of its 64-byte seed, or web↔desktop derive different
// keys for the same identity and every hybrid handshake silently fails.
test("seeded keygen is deterministic (FinBit requirement)", { skip: present ? false : "no vendor file" }, () => {
    const k1 = ml_kem768.keygen(seedA);
    const k2 = ml_kem768.keygen(seedA);
    assert.ok(eq(k1.publicKey, k2.publicKey), "same seed → same publicKey");
    assert.ok(eq(k1.secretKey, k2.secretKey), "same seed → same secretKey");
    const k3 = ml_kem768.keygen(seedB);
    assert.ok(!eq(k1.publicKey, k3.publicKey), "different seed → different publicKey");
});

// FIPS-203 §6.3 implicit rejection: decapsulation NEVER fails. A corrupted
// ciphertext yields a deterministic pseudo-random shared secret (derived from
// the secret key's z value), NOT an error and NOT the genuine SS. A stub /
// truncated / tampered bundle won't reproduce this — strong "is it real
// ML-KEM" signal beyond a plain round-trip.
test("implicit rejection on corrupted ciphertext (FIPS-203)", { skip: present ? false : "no vendor file" }, () => {
    const { publicKey, secretKey } = ml_kem768.keygen(seedA);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    const bad = Uint8Array.from(cipherText);
    bad[0] ^= 0xff;   // flip a bit
    let rejected;
    assert.doesNotThrow(() => { rejected = ml_kem768.decapsulate(bad, secretKey); },
        "decapsulate must not throw on a bad ciphertext");
    assert.equal(rejected.length, SS, "implicit-rejection SS is still 32B");
    assert.ok(!eq(rejected, sharedSecret), "implicit-rejection SS differs from the genuine SS");
    // Implicit rejection is itself deterministic in the (ct, sk) pair.
    const again = ml_kem768.decapsulate(bad, secretKey);
    assert.ok(eq(rejected, again), "implicit-rejection SS is deterministic");
});
