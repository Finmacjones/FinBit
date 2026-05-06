// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Two layers of notifications:
//
//   1. Foreground / in-tab: when a DM arrives and `document.hidden` is
//      true (tab in background), show a Notification via the system's
//      notification API. This is what handles the common "I've got the
//      tab open in another window" case. No service worker required.
//
//   2. Push: registers the service worker (sw.js) and asks the user
//      for the standard Notification permission. Push subscription
//      against the relay's VAPID key is wired but stubbed — the relay
//      doesn't yet send real Web Push messages (separate workstream),
//      so this layer's main effect today is to warm up the SW so future
//      relay-side work just lights up.
//
// Both layers are no-ops if the user hasn't granted permission, or if
// the browser doesn't support the relevant API.

'use strict';

let _swReg = null;

// Ask for permission once and cache. Returns true if we have permission.
export async function requestPermission() {
    if (typeof Notification === "undefined") return false;
    if (Notification.permission === "granted") return true;
    if (Notification.permission === "denied")  return false;
    try {
        const r = await Notification.requestPermission();
        return r === "granted";
    } catch { return false; }
}

// Register the service worker. Returns the registration or null.
export async function registerSw() {
    if (!("serviceWorker" in navigator)) return null;
    try {
        _swReg = await navigator.serviceWorker.register("/ui/sw.js", { scope: "/ui/" });
        return _swReg;
    } catch (e) {
        console.warn("[FinBit] service worker register failed:", e);
        return null;
    }
}

// Show an in-tab Notification (no SW needed). Use for live messages
// that arrive while the tab is in the background.
export function showLocal(title, body) {
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "granted") return;
    if (!document.hidden) return;   // user is looking; don't be noisy
    try {
        const n = new Notification(title, { body, tag: "finbit-msg" });
        n.onclick = () => { window.focus(); n.close(); };
    } catch { /* private mode etc. */ }
}

// Subscribe to Web Push using the relay's VAPID public key. Returns
// the PushSubscription or null. The caller is responsible for shipping
// `subscription.toJSON()` over to the relay so the relay can deliver
// pushes to it.
//
// vapidPublicKeyB64Url: the relay's VAPID public key in base64url form.
// If the relay doesn't expose one, we skip subscription (tab-foreground
// notifications still work).
export async function subscribeToPush(vapidPublicKeyB64Url) {
    if (!_swReg)                        return null;
    if (!_swReg.pushManager)             return null;
    if (!vapidPublicKeyB64Url)           return null;
    try {
        const existing = await _swReg.pushManager.getSubscription();
        if (existing) return existing;
        const key = b64urlToBytes(vapidPublicKeyB64Url);
        return await _swReg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: key,
        });
    } catch (e) {
        console.warn("[FinBit] push subscribe failed:", e);
        return null;
    }
}

function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
