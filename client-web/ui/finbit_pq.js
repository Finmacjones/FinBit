// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FinBit web PQ adapter (Tier 7).
//
// Wires a vendored ML-KEM-768 implementation into FinBit's hybrid handshake.
// Dynamic-import seam: the adapter looks for `./vendor/noble-mlkem.mjs`. When
// the file is present and exports `ml_kem768`, PQ is enabled and the web
// client publishes a real pq_pubkey + signs envelopes with pq_ct. When the
// file is absent (the default in a fresh checkout — vendoring is a deliberate
// supply-chain decision and must be done by a human), the adapter falls back
// to no-op stubs and the wire format degrades cleanly to X25519-only.
//
// VENDORING — see client-web/ui/vendor/README.md for the full instructions.
// In short: the vendor file must export an `ml_kem768` object with this API,
// matching @noble/post-quantum's ml-kem.js:
//
//   ml_kem768.keygen(seed64?: Uint8Array)                       // → {secretKey, publicKey}
//   ml_kem768.encapsulate(publicKey, randomness?: Uint8Array)   // → {cipherText, sharedSecret}
//   ml_kem768.decapsulate(cipherText, secretKey)                // → sharedSecret
//
// Sizes (FIPS-203 ML-KEM-768): seed=64, publicKey=1184, secretKey=2400,
// cipherText=1088, sharedSecret=32.
//
// HKDF-SHA256 (for the X25519+ML-KEM combiner and the PQ-seed derivation)
// uses the browser's WebCrypto SubtleCrypto so we don't have to vendor a
// second crypto library. SubtleCrypto.deriveBits with HKDF is a baseline
// browser feature (Chromium 60+, Firefox 60+, Safari 11+, Node 16+).
//
// The four salt/info strings below MUST stay byte-identical to the desktop
// (fb::crypto::derive_pq_seed_from_identity_seed,
//  fb::crypto::hybrid::combine_x25519_mlkem768) — or the web client and the
// desktop client derive different keys for the same identity / session, and
// hybrid handshakes silently fail to interoperate.

'use strict';

const EMPTY = new Uint8Array(0);

// Domain-separation constants — see core/src/handshake/hybrid.cpp and
// core/src/crypto/hybrid_kem.cpp. These bytes are the contract.
const PQ_SEED_INFO    = new TextEncoder().encode("FinBit-PQ-seed-v1");
const HYBRID_SALT     = new TextEncoder().encode("FinBit-hybrid-v1");
const HYBRID_INFO     = new TextEncoder().encode("FinBit hybrid X25519+ML-KEM-768");
const EMPTY_SALT      = new Uint8Array(0);

// ---- Dynamic import of the vendored ML-KEM-768 ---------------------------
// Top-level await means the module load resolves once the vendor probe is
// done; consumers that `import * as PQ from "./finbit_pq.js"` get a
// fully-initialized adapter without any runtime probing.
let _mlKem768 = null;
try {
    const m = await import("./vendor/noble-mlkem.mjs");
    _mlKem768 = m.ml_kem768 || m.default?.ml_kem768 || null;
} catch (_e) {
    _mlKem768 = null;
}

// True when a real ML-KEM-768 has loaded. The call sites in finbit_conn.js
// gate every PQ operation on this — false means EVERY function below
// returns empty / unchanged.
export function pqEnabled() { return _mlKem768 !== null; }

// ---- HKDF-SHA256 via WebCrypto -------------------------------------------
async function _hkdfBits(salt, ikm, info, lengthBytes) {
    const subtle = (globalThis.crypto || globalThis.self?.crypto).subtle;
    if (!subtle) {
        throw new Error("finbit_pq: WebCrypto.subtle unavailable");
    }
    const ikmKey = await subtle.importKey("raw", ikm, "HKDF", false,
                                           ["deriveBits"]);
    const bits = await subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info },
        ikmKey, lengthBytes * 8);
    return new Uint8Array(bits);
}

// ---- Public API ----------------------------------------------------------

// Derive the deterministic ML-KEM-768 keypair + the Ed25519 binding sig over
// the pubkey. Mirrors fb::handshake::derive_pq_identity on desktop:
//   pqSeed64 = HKDF-SHA256(salt=empty, ikm=identitySeed,
//                           info="FinBit-PQ-seed-v1", L=64)
//   { pub, sec } = ml_kem768.keygen(pqSeed64)
//   pubkeySig    = Ed25519-sign(identity, pub)
//
// Args:
//   seed: Uint8Array(32) — the 32-byte Ed25519 identity seed
//   signWithIdentity: async (msg) => Uint8Array(64) — Ed25519 detached sig
//     using the identity secret. The web client passes `client.sign` here;
//     it's sync today but we await defensively to allow async backends.
// Returns: { pub: Uint8Array(1184), sec: Uint8Array(2400),
//            pubkeySig: Uint8Array(64) }
//   When PQ is off (vendor absent), all three are empty.
export async function derivePqIdentity(seed, signWithIdentity) {
    if (!pqEnabled()) {
        return { pub: EMPTY, sec: EMPTY, pubkeySig: EMPTY };
    }
    const pqSeed = await _hkdfBits(EMPTY_SALT, seed, PQ_SEED_INFO, 64);
    const kp = _mlKem768.keygen(pqSeed);
    const pub = kp.publicKey || kp.pub;
    const sec = kp.secretKey || kp.sec;
    if (pub.length !== 1184 || sec.length !== 2400) {
        throw new Error(`finbit_pq: ML-KEM-768 keygen returned unexpected `
                        + `sizes (pub=${pub.length} sec=${sec.length})`);
    }
    const sig = await signWithIdentity(pub);
    return { pub, sec, pubkeySig: sig };
}

// Encapsulate against a peer's pq_pubkey. Sync — noble's encap is sync.
// Returns { ct: Uint8Array(1088), ss: Uint8Array(32) }. Empty when PQ is off.
export function encapForPeer(peerPqPub) {
    if (!pqEnabled() || !peerPqPub || peerPqPub.length !== 1184) {
        return { ct: EMPTY, ss: EMPTY };
    }
    const out = _mlKem768.encapsulate(peerPqPub);
    return {
        ct: out.cipherText || out.ct,
        ss: out.sharedSecret || out.ss,
    };
}

// Decapsulate with our own pq_sec. Sync — noble's decap is sync.
// Returns Uint8Array(32) shared secret, or empty when PQ is off / inputs bad.
export function decapWithOwn(ct, ownPqSec) {
    if (!pqEnabled() || !ct || ct.length !== 1088
        || !ownPqSec || ownPqSec.length !== 2400) {
        return EMPTY;
    }
    return _mlKem768.decapsulate(ct, ownPqSec);
}

// HKDF-combine the X25519 shared secret with the ML-KEM shared secret.
// Mirrors fb::crypto::hybrid::combine_x25519_mlkem768 byte-for-byte:
//   PRK = HKDF-Extract(salt="FinBit-hybrid-v1", IKM=ss_x25519 || ss_mlkem768)
//   out = HKDF-Expand(PRK, info="FinBit hybrid X25519+ML-KEM-768", L=32)
//
// Async because WebCrypto is async. If `ssMlkem` is empty (PQ off or peer
// is pre-PQ), returns ssX25519 unchanged — the X25519-only behavior that
// pre-PQ peers still produce.
export async function combineX25519Mlkem768(ssX25519, ssMlkem) {
    if (!ssMlkem || ssMlkem.length === 0) return ssX25519;
    if (ssX25519.length !== 32 || ssMlkem.length !== 32) {
        throw new Error(`finbit_pq: combine inputs wrong size `
                        + `(x25519=${ssX25519.length} mlkem=${ssMlkem.length})`);
    }
    const ikm = new Uint8Array(64);
    ikm.set(ssX25519, 0);
    ikm.set(ssMlkem, 32);
    return _hkdfBits(HYBRID_SALT, ikm, HYBRID_INFO, 32);
}
