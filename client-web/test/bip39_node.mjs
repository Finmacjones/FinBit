// SPDX-License-Identifier: AGPL-3.0-or-later
// BIP39 round-trip + KAT smoke.
//
// Two assertions:
//   1. seedToPhrase / phraseToSeed round-trip preserves the seed byte-for-byte.
//   2. The official BIP39 test vectors (subset for 256-bit entropy) decode
//      to the documented seed and word list — proves we're spec-compliant.

import { seedToPhrase, phraseToSeed } from "../ui/bip39.js";
import assert from "node:assert/strict";

// ---- 1. round-trip 100 random seeds ----------------------------------------
for (let i = 0; i < 100; i++) {
    const s = new Uint8Array(32);
    crypto.getRandomValues(s);
    const phrase = await seedToPhrase(s);
    const back   = await phraseToSeed(phrase);
    assert.deepEqual(back, s, `round-trip fail at i=${i}`);
}
console.log("OK 100 random round-trips");

// ---- 2. official BIP39 test vector (256-bit entropy = 32-byte seed) --------
// From github.com/trezor/python-mnemonic/blob/master/vectors.json (English):
//   entropy: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
//   mnemonic: zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo
//             zoo zoo zoo zoo zoo zoo zoo vote
{
    const entropy = new Uint8Array(32).fill(0xff);
    const expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo " +
                     "zoo zoo zoo zoo zoo zoo zoo vote";
    const got = await seedToPhrase(entropy);
    assert.equal(got, expected, `KAT 0xFF*32 mismatch: got "${got}"`);
    const back = await phraseToSeed(expected);
    assert.deepEqual(back, entropy, "KAT 0xFF*32 reverse mismatch");
}
console.log("OK BIP39 official vector (0xFF*32 → \"zoo … vote\")");

// All-zero entropy KAT.
{
    const entropy = new Uint8Array(32);
    const expected = "abandon abandon abandon abandon abandon abandon abandon abandon " +
                     "abandon abandon abandon abandon abandon abandon abandon abandon " +
                     "abandon abandon abandon abandon abandon abandon abandon art";
    const got = await seedToPhrase(entropy);
    assert.equal(got, expected, `KAT 0x00*32 mismatch: got "${got}"`);
}
console.log("OK BIP39 official vector (0x00*32 → \"abandon … art\")");

// ---- 3. checksum-mismatch rejection ----------------------------------------
{
    const phrase = await seedToPhrase(new Uint8Array(32));
    // Swap the last word ("art") for one that breaks the checksum.
    const broken = phrase.replace(/\bart\b/, "ability");
    let threw = false;
    try { await phraseToSeed(broken); } catch { threw = true; }
    assert.ok(threw, "phraseToSeed must reject a phrase with a wrong checksum");
}
console.log("OK checksum mismatch rejected");

// ---- 4. unknown word rejection ---------------------------------------------
{
    let threw = false;
    try { await phraseToSeed("bogus".repeat(24).match(/.{5}/g).join(" ").replaceAll("bogus", "bogus ").trim()); }
    catch { threw = true; }
    // (the malformed input above also has a length / dict miss; we just want SOMETHING to throw)
    assert.ok(threw, "phraseToSeed must reject obviously-wrong input");
}
console.log("OK garbage input rejected");

console.log("PASS: bip39 round-trip + spec-compliance smoke.");
