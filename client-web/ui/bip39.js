// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Minimal BIP39 encode/decode for the 32-byte FinBit identity seed.
//
//   32-byte seed (256 bits) + SHA-256(seed)[0..7] (8 checksum bits) = 264 bits
//                                                                  = 24 × 11-bit chunks
//   Each 11-bit chunk indexes into the 2048-word English wordlist.
//
// Round-trip: seed → 24 words → seed.  Recovery from 24 words is rejected
// if the embedded checksum doesn't match — protects against typos.
//
// We accept the BIP39 canonical wordlist and produce 24-word phrases.
// Smaller word counts (12 / 18) aren't supported; we always have 32 bytes.
//
// SHA-256 comes from WebCrypto (browsers + Node 22).

import { BIP39_EN } from "./bip39_wordlist.js";

if (BIP39_EN.length !== 2048) {
    throw new Error(`bip39: wordlist must be exactly 2048 entries (got ${BIP39_EN.length})`);
}

// Build a fast lookup: word → index. Throws if a word is unknown.
const _index = new Map(BIP39_EN.map((w, i) => [w, i]));
function indexOf(w) {
    const i = _index.get(w);
    if (i === undefined) throw new Error(`bip39: unknown word "${w}"`);
    return i;
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// 32-byte seed → 24-word phrase (space-separated, lowercase).
export async function seedToPhrase(seed) {
    if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) {
        throw new Error("seedToPhrase: seed must be Uint8Array(32)");
    }
    // 256 bits + 8 checksum bits = 264 bits = 33 bytes laid out as
    // [seed(32)][checksum_top_8_bits_of_sha256_of_seed (1 byte)].
    const cs = (await sha256(seed))[0];
    const ent = new Uint8Array(33);
    ent.set(seed, 0);
    ent[32] = cs;

    // Walk 264 bits in 11-bit chunks (24 of them).
    const words = new Array(24);
    for (let i = 0; i < 24; i++) {
        let v = 0;
        for (let b = 0; b < 11; b++) {
            const bit = i * 11 + b;          // bit position in `ent`
            const byte = ent[bit >> 3];
            const off  = 7 - (bit & 7);
            v = (v << 1) | ((byte >> off) & 1);
        }
        words[i] = BIP39_EN[v];
    }
    return words.join(" ");
}

// 24-word phrase → 32-byte seed. Throws on:
//   * not exactly 24 whitespace-separated tokens
//   * unknown word
//   * checksum mismatch
//
// Whitespace and case are normalized; capitalization is ignored.
export async function phraseToSeed(phrase) {
    const words = phrase
        .normalize("NFKD")
        .toLowerCase()
        .trim()
        .split(/\s+/)
        .filter(Boolean);
    if (words.length !== 24) {
        throw new Error(`bip39: phrase must have 24 words (got ${words.length})`);
    }
    // Pack 24 × 11-bit indices into a 264-bit big-endian buffer.
    const ent = new Uint8Array(33);
    let bitpos = 0;
    for (const w of words) {
        let v = indexOf(w);
        for (let b = 10; b >= 0; b--) {
            const byte = bitpos >> 3;
            const off  = 7 - (bitpos & 7);
            ent[byte] |= ((v >> b) & 1) << off;
            bitpos++;
        }
    }
    const seed = ent.slice(0, 32);
    const expected = (await sha256(seed))[0];
    if (ent[32] !== expected) {
        throw new Error("bip39: checksum mismatch — typo in the recovery phrase?");
    }
    return seed;
}
