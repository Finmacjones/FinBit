// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FinBit service worker. Handles the Web Push `push` event so the OS
// shows a notification when a message arrives while the tab is closed
// (or in the background).
//
// What this DOESN'T do:
//   * Decrypt the envelope. The push payload is opaque ("you have a
//     new message") because the SW doesn't have access to the seed in
//     IndexedDB without re-running the full WASM crypto stack — and
//     loading the WASM module + opening the vault inside an SW is
//     possible but adds a lot of cost. v0 keeps the notification
//     generic; the user clicks → we open the page → the page connects
//     and drains.
//
// What this needs to actually fire:
//   The web client (push.js) must register THIS file as the service
//   worker AND register a Web Push subscription against the relay's
//   VAPID public key. AND the relay must implement actual Web Push
//   delivery (separate workstream — see docs/ROADMAP.md).
//
// Until then, this SW is wired but mostly dormant — the in-tab
// Notification path in app.js handles the foreground case.

self.addEventListener('install',  () => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });

self.addEventListener('push', (event) => {
    let body = "You have a new message";
    try {
        if (event.data) {
            const txt = event.data.text();
            if (txt && txt.length > 0) body = txt;
        }
    } catch { /* opaque payload — fine */ }
    event.waitUntil(self.registration.showNotification("FinBit", {
        body,
        icon: '/ui/icon-192.png',     // optional; harmless if missing
        badge: '/ui/badge-72.png',
        tag: 'finbit-msg',             // collapses repeat pushes
    }));
});

// Click → focus an existing FinBit tab if one's open, else open a new one.
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    event.waitUntil((async () => {
        const clientsList = await self.clients.matchAll({
            type: 'window', includeUncontrolled: true,
        });
        for (const client of clientsList) {
            if (client.url.includes('/ui/')) {
                return client.focus();
            }
        }
        return self.clients.openWindow('/ui/');
    })());
});
