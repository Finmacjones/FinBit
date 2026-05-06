// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Persistent list of FinBit relays the user has added. Lives in the
// existing finbit IndexedDB (alongside the identity vault + outbox). One
// record per relay, schema:
//
//   { id (autoinc), url, username, label, addedAt, isDefault }
//
// `label` is what shows under the icon in the server rail (defaults to
// the URL hostname). `isDefault` is the relay we auto-connect to on
// boot — there's exactly one default at any time.
//
// Same identity (same seed) is used across all relays — each relay
// independently runs the username-binding challenge-response, so the
// user's pubkey is the same person on every relay. Server-side
// federation (cross-relay routing) is a separate piece of work
// documented in docs/ROADMAP.md.

'use strict';

const DB_NAME    = "finbit";
const DB_VERSION = 3;     // bump from 2 (vault + outbox) → 3 (+ servers)
const STORE      = "servers";

function openDB() {
    return new Promise((resolve, reject) => {
        if (typeof indexedDB === "undefined") {
            return reject(new Error("IndexedDB unavailable"));
        }
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains("identity"))
                db.createObjectStore("identity");
            if (!db.objectStoreNames.contains("outbox")) {
                const o = db.createObjectStore("outbox",
                    { keyPath: "id", autoIncrement: true });
                o.createIndex("queuedAt", "queuedAt", { unique: false });
            }
            if (!db.objectStoreNames.contains(STORE)) {
                db.createObjectStore(STORE,
                    { keyPath: "id", autoIncrement: true });
            }
        };
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

function hostnameOf(url) {
    try { return new URL(url.replace(/^ws/, "http")).hostname; }
    catch { return url; }
}

// Returns all known servers, oldest-first. Default relay (the one
// auto-connected on boot) is somewhere in the list with isDefault=true.
export async function list() {
    if (typeof indexedDB === "undefined") return [];
    const db = await openDB();
    try {
        return await new Promise((resolve, reject) => {
            const t = db.transaction(STORE, "readonly");
            const req = t.objectStore(STORE).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror   = () => reject(req.error);
        });
    } finally { db.close(); }
}

// Append a new relay. If it's the first one, automatically marked as
// default. Returns the auto-assigned id.
export async function add({ url, username, label }) {
    if (!url) throw new Error("server_book.add: url required");
    const existing = await list();
    const isFirst = existing.length === 0;
    const entry = {
        url: url.trim(),
        username: (username || "").trim(),
        label: (label || hostnameOf(url)).trim(),
        addedAt: Date.now(),
        isDefault: isFirst,
    };
    const db = await openDB();
    try {
        return await new Promise((resolve, reject) => {
            const t = db.transaction(STORE, "readwrite");
            const req = t.objectStore(STORE).add(entry);
            req.onsuccess = () => resolve(req.result);
            req.onerror   = () => reject(req.error);
        });
    } finally { db.close(); }
}

// Remove a relay by id. If it was the default, the next-oldest becomes
// the new default.
export async function remove(id) {
    const db = await openDB();
    try {
        await new Promise((resolve, reject) => {
            const t = db.transaction(STORE, "readwrite");
            t.objectStore(STORE).delete(id);
            t.oncomplete = () => resolve();
            t.onerror    = () => reject(t.error);
        });
    } finally { db.close(); }
    // Re-balance the default flag.
    const remaining = await list();
    if (!remaining.some((s) => s.isDefault) && remaining.length > 0) {
        await setDefault(remaining[0].id);
    }
}

// Mark `id` as the new default (clears the flag on every other entry).
export async function setDefault(id) {
    const all = await list();
    const db = await openDB();
    try {
        await new Promise((resolve, reject) => {
            const t = db.transaction(STORE, "readwrite");
            const s = t.objectStore(STORE);
            for (const rec of all) {
                rec.isDefault = (rec.id === id);
                s.put(rec);
            }
            t.oncomplete = () => resolve();
            t.onerror    = () => reject(t.error);
        });
    } finally { db.close(); }
}

// Convenience: returns the default relay, or null if the list is empty.
export async function getDefault() {
    const all = await list();
    return all.find((s) => s.isDefault) || all[0] || null;
}
