// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FinBit web PQ adapter (Tier 7 hook).
//
// This module is the SINGLE seam where the web client integrates a
// post-quantum KEM (ML-KEM-768) for hybrid key exchange. The desktop
// and CLI clients use OpenSSL 3.5+'s native ML-KEM (via fb::handshake),
// but the browser WASM build doesn't link OpenSSL — so the web client
// needs either a pure-JS implementation, a WebCrypto polyfill (none
// standardized yet for ML-KEM as of 2026), or a custom emscripten build
// with PQ baked in.
//
// THIS DEFAULT IMPLEMENTATION returns empty bytes for every PQ-shaped
// API. Empty pq_pubkey / pq_pubkey_sig / pq_ct cleanly trigger the
// X25519-only fallback path on every peer that supports the PQ wire
// format — so web clients still interop with PQ-aware desktops, they
// just don't get harvest-now-decrypt-later protection on their own
// envelopes. The wire surface is in place; flipping to real PQ is a
// drop-in replacement of the four functions below.
//
// ---------------------------------------------------------------------------
// Vendoring guide — to actually enable PQ on the web:
// ---------------------------------------------------------------------------
// Option A (recommended): drop @noble/post-quantum's ml-kem-768 module
// next to this file as `vendor/noble-mlkem-768.mjs` and import it. The
// noble libraries are pure JS, audited, and ship as standard ESM:
//
//    import { ml_kem768 } from "./vendor/noble-mlkem-768.mjs";
//    // keygenFromSeed(seed) — noble exposes ml_kem768.keygen() taking a
//    //   64-byte seed via the `seed` parameter (FIPS-203 d || z).
//    // encap(pub) → { cipherText, sharedSecret }
//    // decap(ct, sec) → sharedSecret
//
// Option B: build a custom WASM that includes OpenSSL ML-KEM (or
// liboqs), expose it via emscripten bindings in client-web/wasm-shim,
// and call into it from this adapter.
//
// Option C: when WebCrypto adds ML-KEM (Tracking: W3C TPAC 2025
// PQ-Crypto WG), replace the noble import with a SubtleCrypto wrapper.
//
// All three options keep the wire format and the call sites in
// finbit_conn.js unchanged — they only swap out the four `pq_*`
// functions in this file.
// ---------------------------------------------------------------------------

const EMPTY = new Uint8Array(0);

// Deterministic ML-KEM-768 keypair derived from the 32-byte Ed25519
// identity seed, plus an Ed25519 signature over pq.pub by the identity
// (matches fb::handshake::derive_pq_identity on the desktop side so a
// web user and a desktop user with the SAME seed produce the same PQ
// identity).
//
// Default implementation: returns empty bytes → no pq_pubkey published
// → peers fall back to X25519. Vendoring a real ML-KEM lights this up.
//
// Args:
//   seed: Uint8Array(32) — Ed25519 identity seed
//   signWithIdentity: (msg: Uint8Array) => Uint8Array(64) — produces an
//     Ed25519 detached signature over msg using the identity secret
//     (typically `wasm.sign` via the WebClient binding)
// Returns: { pub: Uint8Array, sec: Uint8Array, pubkeySig: Uint8Array }
//   When unsupported (this default), all three are empty.
export function derivePqIdentity(seed, signWithIdentity) {
    void seed;
    void signWithIdentity;
    return { pub: EMPTY, sec: EMPTY, pubkeySig: EMPTY };
}

// Caller-side: encapsulate against the peer's pq_pubkey. Returns the
// (1088-byte) ciphertext to ship in Envelope.pq_ct + the 32-byte shared
// secret to feed into the hybrid HKDF.
//
// Args:
//   peerPqPub: Uint8Array(1184) — peer's ML-KEM-768 public key
// Returns: { ct: Uint8Array, ss: Uint8Array(32) }
//   When unsupported, ct + ss are both empty → caller falls back to pure X25519.
export function encapForPeer(peerPqPub) {
    void peerPqPub;
    return { ct: EMPTY, ss: EMPTY };
}

// Receiver-side: decapsulate the ciphertext from Envelope.pq_ct with our
// own ML-KEM-768 secret key. Returns the recovered 32-byte shared secret.
// When unsupported, returns empty → caller falls back to pure X25519.
export function decapWithOwn(ct, ownPqSec) {
    void ct;
    void ownPqSec;
    return EMPTY;
}

// HKDF-combine the X25519 shared secret with the ML-KEM shared secret
// using the same salt/info that fb::crypto::hybrid::combine_x25519_mlkem768
// uses on the desktop side — so the same hybrid root is derived bit-for-
// bit on both sides.
//
// Default implementation: returns ssX25519 unchanged (since real ML-KEM
// isn't here, there's no hybrid to combine). When a real PQ implementation
// is dropped in, this becomes a real HKDF-Extract+Expand mirroring the
// C++ helper.
//
// The HKDF parameters MUST stay synchronized with
// core/src/crypto/hybrid_kem.cpp:
//   salt = "FinBit-hybrid-v1"
//   info = "FinBit hybrid X25519+ML-KEM-768"
//   L    = 32
export function combineX25519Mlkem768(ssX25519, ssMlkem) {
    if (!ssMlkem || ssMlkem.length === 0) return ssX25519;
    // Real impl belongs here once a JS HKDF + ML-KEM are present.
    // Until then any caller of this function MUST hold ssMlkem.length === 0
    // (because the only path that produces a non-empty ssMlkem also drops
    // a real combiner in).
    throw new Error("finbit_pq: combineX25519Mlkem768 unimplemented — "
                    + "vendor a JS HKDF alongside ML-KEM (see top-of-file guide)");
}

// Feature-flag: true when the adapter has a real ML-KEM implementation
// behind it. Used by finbit_conn / finbit_proto to decide whether to
// publish pq_pubkey + encap on send / decap on recv at all. Default false.
export function pqEnabled() {
    return false;
}
