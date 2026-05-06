<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Roadmap

What's intentionally **not** in v1.0.1, with an honest estimate of what
each item actually costs to land. Sorted roughly by user-visible impact,
not by effort.

## Polish — quick to add (a few hours each)

### ~~Remote video widget on desktop~~ — **shipped**
The inbound video chain now ends in an `appsink` instead of
`autovideosink`. Each decoded frame is pulled, copied into a `QImage`,
and emitted as `MediaCall::remoteVideoFrame`; `MainWindow` paints it
into a 160×90 `QLabel` embedded in the active-call banner.

### ~~SFrame layered on the desktop call~~ — **shipped**
`MediaCall::set_sframe_context(shared, call_id)` derives the per-call
base key the same way the web client does (HKDF over the X3DH shared
secret + the call_id), and `gst_pad_add_probe` installs send-side
seal probes on `opusenc`/`vp8enc` SRC pads and recv-side open probes
on `rtpopusdepay`/`rtpvp8depay` SRC pads. Wire format matches
`client-web/ui/media_call.js` byte-for-byte. Failed `sframe_open` =
the buffer is dropped at the probe (forged frames never reach the
decoder).

### In-server TLS
**Status:** the server speaks plain TCP / WebSocket. For TLS, front it
with a reverse proxy (caddy / nginx / traefik). The `--help` text and
README ship a Caddyfile snippet.
**Cost:** ~1 day (the easy 30-minute bit is `SSL_*`; the ~1 day is the
cert lifecycle: load on startup, watch for renewal, ALPN selection,
SNI for multi-domain, ACME if we don't want to outsource it).
**Why deferred:** every comparable relay daemon (Postgres, Redis,
Mosquitto, mediasoup) does the same thing — terminate TLS in a proxy.
Reinventing it inside fb_server adds attack surface for no UX win.

## Real features — half-day to a day

### ~~Offline outbound queue (web client)~~ — **shipped**
`client-web/ui/outbox.js` persists `{recipient, plaintext, queuedAt,
attempts}` to a separate IndexedDB store. `FinBitConnection.sendDm`
queues to the outbox when the WS isn't connected; the post-auth path
in `connect()` calls `Outbox.drain()` which encrypts + sends each
queued entry through the live ratchet. Plaintext (not the ratchet
output) is persisted so the ratchet only steps when the message
actually goes out — a browser restart mid-queue can't desync the
session.

### Push notifications — partial
**Shipped:** Foreground notifications (the in-tab `Notification` API)
fire when a DM or channel message arrives while the tab is in the
background. Service worker (`client-web/ui/sw.js`) is registered and
handles `push` events with the standard system notification path.
**Still deferred:** the actual outbound Web Push delivery from the
relay. Implementing it requires (a) generating + storing a VAPID
keypair on the relay, (b) implementing RFC 8291 payload encryption
(the AES128GCM-with-ECDH content-encoding), (c) shipping VAPID JWT
auth on the outbound push, (d) doing HTTPS POST to FCM / Mozilla
autopush — needs libcurl or a hand-rolled HTTPS client. **Cost:**
~3-4 days of focused work. Until it lands the service worker
infrastructure is wired but mostly dormant; the foreground path
covers the "tab is open in another window" case.

### Federation hint
**Status:** the "+ Add server" button in the rail says "coming soon".
**Cost:** ~1 week. The protocol already supports this — every server is
just a relay; clients can hold multiple connections — but the UI for
managing them, deciding which relay to send a given message through, and
moving identities between relays needs design.

## Multi-week — separate workstreams

### Group voice / video (SFU)
**Cost:** ~3–4 weeks. Stand up a mediasoup or Janus instance, integrate
its signaling protocol on top of our existing MediaSignal frame, route
group calls through it, layer SFrame so the SFU sees only ciphertext
frames. The SFrame primitive is already in `core/src/media/sframe.cpp`.

### MLS (Messaging Layer Security) for channels
**Cost:** ~6–8 weeks. Vendor [mlspp](https://github.com/cisco/mlspp)
(~100k LOC of MLS protocol code), integrate it behind the existing
`fb::crypto::mls_facade` interface, replace SenderKeys at the channel
layer. Wire format change — the new `Envelope.ciphertext` for channels
is an MLS application message instead of a `SenderKeysMessage`.
**Why MLS over SenderKeys eventually:** SenderKeys has no automatic
post-removal exclusion (a removed member's stored chain key still
decrypts old messages); MLS handles add/remove/update via Tree-KEM.
Doesn't matter at the user counts FinBit handles today.

### Windows port
**Status:** server + fb-cli + desktop client are Linux-only today. The
codebase calls `epoll` / `sys/socket` / `termios` / `ifaddrs` /
`sigaction` / `posix_openpt` directly. CI builds + ships only Linux
artifacts (`finbit-linux-x86_64.tar.gz`).
**Cost:** ~3-5 days for a usable Windows port. Needed:
  * `fb::net::IoLoop` — swap epoll for WSAPoll or IOCP
  * `fb::net::Socket` — WinSock2 (`WSAStartup`, `closesocket`,
    `GetLastError` vs errno)
  * `SerialBridge` — `CreateFile` + DCB instead of termios (or skip
    serial on Windows entirely)
  * `external_addresses()` in server — `GetAdaptersAddresses`
  * Server signal handlers — `SetConsoleCtrlHandler`
**Why deferred:** broad surface area, no Windows host on this dev
machine to test against, and most users wanting "FinBit on Windows"
can run Linux binaries via WSL2 today (works out of the box,
fb_server / fb_desktop / fb-cli all run unmodified). A native build
is nice-to-have, not a blocker.

### Android client
**Status:** Kotlin/Compose scaffold + JNI bridge skeleton committed
under `client-mobile-android/`. NDK isn't installed in this dev env.
**Cost:** ~2 weeks once NDK is installed. Cross-compile `fb::core` per
ABI, finish the JNI surface (network + storage; the crypto JNI is
already wired for self-test), Compose UI for DM list / chat / channels.
**Out of scope from this dev box:** building libsodium-android, an
Android device or emulator to test against.

### iOS client — scrapped
Removed from the repo. Linux dev environment can't compile or test
SwiftUI / Obj-C++.

## Out of scope by design

These aren't deferred — they're explicit non-goals.

- **Server-side message storage past the offline window.** The relay
  drops persisted envelopes once the recipient acks. No cloud history.
- **Server-side identity recovery.** If you lose your vault AND your
  recovery code, the identity is gone. The server doesn't have your
  seed and can't help.
- **TLS-terminating reverse proxy bundled with `fb_server`.** Use caddy
  or nginx — they do this better than we ever will.

## How to contribute the deferred items

If you want to work on one of these, open an issue first so we can
agree on the protocol shape. Anything touching `core/proto/*.proto` or
`core/crypto/*` is reviewed extra carefully — see the Contributing
section of the top-level README.
