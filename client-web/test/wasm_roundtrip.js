// SPDX-License-Identifier: AGPL-3.0-or-later
// FinBit WASM smoke test — runs under Node.js.
//
// Loads the WASM module, generates an identity (proves libsodium init works
// in WASM), runs an AES-256-GCM encrypt/decrypt round-trip, asserts the
// recovered plaintext matches.
//
// Use: cd client-web && node test/wasm_roundtrip.js

'use strict';

const FinBitModule = require('../build/finbit.js');
const crypto = require('crypto');
const assert = require('assert');

(async () => {
    const Module = await FinBitModule();

    // ---- identity --------------------------------------------------------
    const fp = Module.generate_identity_fingerprint();
    console.log('IDENTITY:', fp);
    assert.match(fp, /^[A-Z0-9]{5}-[A-Z0-9]{5}$/, 'fingerprint must be XXXXX-XXXXX base32');

    // ---- aead ------------------------------------------------------------
    // ---- AES-256-GCM (only when AES-NI is reachable; usually NOT in WASM)
    if (Module.aes256gcm_supported()) {
        const key   = new Uint8Array(crypto.randomBytes(32));
        const nonce = new Uint8Array(crypto.randomBytes(12));
        const plaintext = new TextEncoder().encode('hello from wasm (aes-gcm)');
        const aad = new TextEncoder().encode('aes-aad');
        const ct = Module.aead_encrypt(key, nonce, plaintext, aad);
        assert.ok(ct.length === plaintext.length + 16);
        const rt = Module.aead_decrypt(key, nonce, ct, aad);
        assert.deepStrictEqual(new Uint8Array(rt), plaintext);
        console.log('AES-GCM-OK');
    } else {
        console.log('SKIP-AES: AES-NI unavailable in this WASM runtime (expected).');
    }

    // ---- XChaCha20-Poly1305 (always-available software path) ------------
    {
        const key   = new Uint8Array(crypto.randomBytes(32));
        const nonce = new Uint8Array(crypto.randomBytes(24));   // 192-bit nonce
        const plaintext = new TextEncoder().encode('hello from wasm (xchacha20)');
        const aad = new TextEncoder().encode('xchacha-aad');

        const ct = Module.xchacha20_encrypt(key, nonce, plaintext, aad);
        assert.ok(ct.length === plaintext.length + 16,
                  `xchacha ciphertext+tag size wrong (got ${ct.length})`);

        const rt = Module.xchacha20_decrypt(key, nonce, ct, aad);
        assert.ok(rt !== null, 'xchacha decrypt returned null on valid ciphertext');
        assert.deepStrictEqual(new Uint8Array(rt), plaintext);
        console.log('XCHACHA-ROUND-TRIP-OK:', new TextDecoder().decode(rt));

        const tampered = new Uint8Array(ct);
        tampered[tampered.length - 1] ^= 0x01;
        const bad = Module.xchacha20_decrypt(key, nonce, tampered, aad);
        assert.strictEqual(bad, null, 'tampered ciphertext should fail to decrypt');
        console.log('XCHACHA-TAMPER-REJECT-OK');
    }

    console.log('PASS: WASM smoke test (identity + XChaCha AEAD round-trip + tamper reject).');
})().catch((e) => {
    console.error('FAIL:', e);
    process.exit(1);
});
