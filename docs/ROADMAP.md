<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Roadmap

What's intentionally **not** in v1.0.1, with an honest estimate of what
each item actually costs to land. Sorted roughly by user-visible impact,
not by effort.

> **Living checklists** (checkbox task lists, kept current as items land):
> - `docs/serverless-group-calls.md` — group voice/video to ~24 **without
>   a dedicated SFU**, large file transfer, screen-share.
> - `docs/censorship-resistance.md` — transport mimicry tiers 1–4.

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

### Group voice / video to ~24 — **without a dedicated SFU**
Direction changed: instead of deploying mediasoup/Janus, FinBit scales
group calls by relocating the *forwarding* function onto participants /
volunteer peers (and optionally the already-E2E-blind relay), keeping the
serverless + E2E posture. Full design, bandwidth math, and a phased
checkbox checklist live in **`docs/serverless-group-calls.md`**.
Short version:
  * **Audio to ~24:** optimized full-mesh (Opus DTX + active-speaker
    selection) — no forwarder needed.
  * **Audio to ~24 / small-room video:** a peer-elected forwarder
    ("relay peer"), SFrame-blind, over the reserved `RoomOffer/Answer/Ice`
    frames.
  * **24-way video:** simulcast + active-speaker selective forwarding +
    a shallow cascade tree so no single node carries O(N²) uplink.
The SFrame primitive (`core/src/media/sframe.cpp`) means every forwarder
sees ciphertext only. **Cost:** lever-by-lever; audio levers are days,
the full 24-way video overlay is multi-week.

### ~~MLS (Messaging Layer Security) for channels~~ — **shipped**
mlspp is vendored behind `fb::crypto::mls_facade` and selectable
per-channel (`ChannelCrypto::kMls`); SenderKeys remains the default.
New MLS channels carry an MLS application message in
`Envelope.ciphertext`; the receive path branches on the per-channel
crypto discriminator. Group state persists via the operation-replay
tables in `sqlite_store`.

### ~~Windows port~~ — **shipped (server + fb-cli + mesh serial; desktop/MLS in CI)**
`fb::net::IoLoop` (WSAPoll), `Socket` (Winsock2), `SerialBridge`
(CreateFile + DCB), `external_addresses` (GetAdaptersAddresses) and
`SetConsoleCtrlHandler` are all ported behind `#ifdef _WIN32`. CI builds
`finbit-windows-x64.zip` on `windows-latest` (MSVC + vcpkg) with a
PowerShell DM-roundtrip canary; the desktop + MLS Windows builds run in
their own workflows. See `docs/windows-port-status.md`.

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
