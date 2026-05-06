// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Persistent outbox for DMs composed while offline (or sent while the
// WebSocket happens to be down). Storage: a separate IndexedDB store
// in the same DB as the identity vault.
//
// Why NOT persist the encrypted Double Ratchet output: the ratchet only
// steps when we actually encrypt + send. If we encrypt-and-queue, then
// the ratchet has stepped but the peer hasn't seen the message — a
// browser restart / drain at a different ratchet position would cause
// a permanent desync. By persisting ONLY the plaintext + recipient, we
// re-encrypt at drain time using the current ratchet state, which is
// always correct.
//
// Each entry:
//   { id: <auto>, recipient: string, plaintext: string, queuedAt: number,
//     attempts: number }
//
// drain() walks the store in queuedAt order and calls the supplied
// `sendFn` for each. On success the entry is removed; on throw it stays
// (with an incremented attempts count) and we move on — the same drain
// will be called again on the next connect.

'use strict';

const DB_NAME    = "finbit";
const DB_VERSION = 2;        // bumped from 1 (vault-only) → 2 (vault + outbox)
const VAULT      = "identity";
const OUTBOX     = "outbox";

function openDB() {
    return new Promise((resolve, reject) => {
        if (typeof indexedDB === "undefined") {
            return reject(new Error("IndexedDB unavailable in this environment"));
        }
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (ev) => {
            const db = req.result;
            // Vault store may already exist from v1; create only if missing.
            if (!db.objectStoreNames.contains(VAULT))  db.createObjectStore(VAULT);
            if (!db.objectStoreNames.contains(OUTBOX)) {
                const s = db.createObjectStore(OUTBOX, {
                    keyPath: "id", autoIncrement: true,
                });
                s.createIndex("queuedAt", "queuedAt", { unique: false });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

function tx(db, mode, fn) {
    return new Promise((resolve, reject) => {
        const t = db.transaction(OUTBOX, mode);
        const s = t.objectStore(OUTBOX);
        const r = fn(s);
        t.oncomplete = () => resolve(r ? r.result : undefined);
        t.onerror    = () => reject(t.error);
        t.onabort    = () => reject(t.error);
    });
}

// Append an entry. Returns the auto-assigned id.
export async function enqueue({ recipient, plaintext }) {
    if (typeof indexedDB === "undefined") return null;
    const entry = {
        recipient, plaintext,
        queuedAt: Date.now(),
        attempts: 0,
    };
    const db = await openDB();
    try {
        const id = await new Promise((resolve, reject) => {
            const t = db.transaction(OUTBOX, "readwrite");
            const s = t.objectStore(OUTBOX);
            const req = s.add(entry);
            req.onsuccess = () => resolve(req.result);
            req.onerror   = () => reject(req.error);
        });
        return id;
    } finally { db.close(); }
}

export async function pending() {
    if (typeof indexedDB === "undefined") return [];
    const db = await openDB();
    try {
        return await new Promise((resolve, reject) => {
            const t = db.transaction(OUTBOX, "readonly");
            const s = t.objectStore(OUTBOX);
            const req = s.getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror   = () => reject(req.error);
        });
    } finally { db.close(); }
}

async function remove(id) {
    const db = await openDB();
    try {
        await new Promise((resolve, reject) => {
            const t = db.transaction(OUTBOX, "readwrite");
            t.objectStore(OUTBOX).delete(id);
            t.oncomplete = () => resolve();
            t.onerror    = () => reject(t.error);
        });
    } finally { db.close(); }
}

async function bumpAttempts(id) {
    const db = await openDB();
    try {
        await new Promise((resolve, reject) => {
            const t = db.transaction(OUTBOX, "readwrite");
            const s = t.objectStore(OUTBOX);
            const get = s.get(id);
            get.onsuccess = () => {
                const rec = get.result;
                if (!rec) return resolve();
                rec.attempts = (rec.attempts || 0) + 1;
                s.put(rec);
            };
            t.oncomplete = () => resolve();
            t.onerror    = () => reject(t.error);
        });
    } finally { db.close(); }
}

// Drain all queued entries in queuedAt order. `sendFn(entry)` should
// return a promise that resolves on success and rejects on failure.
// Successful sends are removed from the store; failures stay queued
// with incremented `attempts`. Returns { sent, failed } counts.
export async function drain(sendFn) {
    const items = await pending();
    items.sort((a, b) => a.queuedAt - b.queuedAt);
    let sent = 0, failed = 0;
    for (const entry of items) {
        try {
            await sendFn(entry);
            await remove(entry.id);
            sent++;
        } catch (e) {
            await bumpAttempts(entry.id);
            failed++;
            // Stop on first failure — the connection is probably still
            // wonky, the next reconnect will retry from where we are.
            break;
        }
    }
    return { sent, failed };
}
