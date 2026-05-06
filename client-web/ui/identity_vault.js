// SPDX-License-Identifier: AGPL-3.0-or-later
// FinBit identity vault — passphrase-protected at-rest storage of the
// 32-byte Ed25519 seed.
//
// IndexedDB layout (DB "finbit", store "identity", key "default"):
//   {
//     version:    2,                        // bumped from v1 (legacy) → v2
//     username:   string,
//     createdAt:  number,
//     // Mutually exclusive: either an encrypted blob, or a legacy raw seed.
//     sealed?:    Uint8Array(104),          // v2 encrypted vault
//     seed?:      Uint8Array(32),           // v1 unencrypted (migration only)
//   }
//
// API design notes:
//   * unlock() does the Argon2id work — slow on purpose. Don't call from
//     a tight loop.
//   * The seed is NEVER returned to the caller in a form that survives
//     reload. Caller hands it straight to WebClient.from_seed() and forgets it.
//   * Multiple identities are out of scope for v0; one record at key "default".

'use strict';

const DB_NAME    = "finbit";
const DB_VERSION = 1;     // IndexedDB schema version (NOT the record version)
const STORE      = "identity";
const KEY        = "default";

const RECORD_VERSION = 2;

// ---------- IndexedDB plumbing ----------

function openDB() {
    return new Promise((resolve, reject) => {
        if (typeof indexedDB === "undefined") {
            return reject(new Error("IndexedDB unavailable in this environment"));
        }
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => req.result.createObjectStore(STORE);
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

function tx(db, mode, fn) {
    return new Promise((resolve, reject) => {
        const t = db.transaction(STORE, mode);
        const s = t.objectStore(STORE);
        const r = fn(s);
        t.oncomplete = () => resolve(r ? r.result : undefined);
        t.onerror    = () => reject(t.error);
        t.onabort    = () => reject(t.error);
    });
}

async function readRecord() {
    const db = await openDB();
    try { return await tx(db, "readonly", (s) => s.get(KEY)); }
    finally { db.close(); }
}

async function writeRecord(rec) {
    const db = await openDB();
    try { await tx(db, "readwrite", (s) => s.put(rec, KEY)); }
    finally { db.close(); }
}

// ---------- vault status ----------

// Returns one of:
//   "absent"  — no vault exists; user must create one
//   "locked"  — encrypted vault exists; user must enter passphrase
//   "legacy"  — unencrypted v1 record; user can sign in without passphrase
//               but should be prompted to upgrade
//   "error"   — IndexedDB read failed; the vault may exist but is
//               currently unreadable. Caller MUST NOT fall through to
//               createVault (would silently overwrite).
export async function vaultStatus() {
    let rec;
    try { rec = await readRecord(); }
    catch (e) {
        // Distinguish a real backend failure (quota / OS error / locked DB)
        // from a missing record; the latter manifests as a successful read
        // returning undefined, not as a thrown error.
        return "error";
    }
    if (!rec) return "absent";
    if (rec.sealed && rec.sealed.byteLength) return "locked";
    if (rec.seed   && rec.seed.byteLength === 32) return "legacy";
    return "absent";
}

// Pull the underlying read error so the UI can surface it. Returns null
// when the read succeeded (or hasn't been attempted yet via vaultStatus).
export async function vaultErrorMessage() {
    try { await readRecord(); return null; }
    catch (e) { return e?.message || String(e); }
}

export async function getMetadata() {
    let rec;
    try { rec = await readRecord(); }
    catch { return null; }
    if (!rec) return null;
    return { username: rec.username || "", createdAt: rec.createdAt || 0 };
}

// ---------- create / unlock / sign out ----------

// Create a new vault. If passphrase is empty/null the seed is stored
// UNENCRYPTED (legacy mode) — useful when the user wants to defer the
// passphrase decision. They can upgrade later via createVault again.
export async function createVault({ Module, username, passphrase, seed }) {
    if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) {
        throw new Error("createVault: seed must be Uint8Array(32)");
    }
    if (passphrase) {
        const sealed = Module.seal_seed(passphrase, seed);
        await writeRecord({
            version: RECORD_VERSION,
            username,
            createdAt: Date.now(),
            sealed: new Uint8Array(sealed),
        });
    } else {
        await writeRecord({
            version: 1,
            username,
            createdAt: Date.now(),
            seed: new Uint8Array(seed),
        });
    }
}

// Unlock and return the 32-byte seed. For legacy records, passphrase is
// ignored. Returns null on wrong passphrase / corrupted vault.
export async function unlock({ Module, passphrase }) {
    const rec = await readRecord();
    if (!rec) return null;
    if (rec.seed && rec.seed.byteLength === 32) {
        return new Uint8Array(rec.seed);   // legacy
    }
    if (!rec.sealed) return null;
    const opened = Module.open_seed(passphrase || "", rec.sealed);
    if (!opened) return null;
    return new Uint8Array(opened);
}

// Re-encrypt an existing seed with a new passphrase. Used by the upgrade
// path (legacy → encrypted) and "change passphrase" flows.
export async function rekey({ Module, seed, username, passphrase }) {
    return createVault({ Module, username, passphrase, seed });
}

// Wipe the persisted vault. The caller is responsible for forgetting
// any in-memory copy of the seed.
export async function signOut() {
    try {
        const db = await openDB();
        try { await tx(db, "readwrite", (s) => s.delete(KEY)); }
        finally { db.close(); }
    } catch { /* nothing to delete */ }
}

// ---------- recovery code ----------
//
// v0 format: 64 lowercase hex chars (the raw seed). Plain hex is the
// least-friendly option but adds no wordlist dependency; a 24-word BIP39
// mapping is a future upgrade.

export function seedToRecoveryHex(seed) {
    if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) {
        throw new Error("seedToRecoveryHex: seed must be Uint8Array(32)");
    }
    return [...seed].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function recoveryHexToSeed(hex) {
    const clean = hex.trim().toLowerCase().replace(/\s+/g, "");
    if (!/^[0-9a-f]{64}$/.test(clean)) {
        throw new Error("recovery code must be 64 hex characters (32 bytes)");
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
