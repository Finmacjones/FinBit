# Changelog

All notable changes to FinBit. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver from
v1.0.1 onward.

## [v1.0.1] — initial public release

### Added
- **End-to-end DM** via the Signal Double Ratchet over libsodium. AES-256-GCM
  on native targets; XChaCha20-Poly1305 in the WASM build (no AES-NI in the
  browser).
- **Channels** via SenderKeys group encryption — per-(group, sender)
  symmetric chains with replay rejection, out-of-order delivery, post-
  eviction key invalidation. Invitees join via a `channel_key` DM.
- **Passphrase-protected identity vault** at rest. Argon2id MODERATE tier
  (~256 MiB / ~1.5 s) → XChaCha20-Poly1305. v2 format binds KDF params
  into AEAD AAD so a write-capable attacker can't downgrade work factor.
  v1 vaults still readable for migration; only v2 written.
- **Server-side username binding** via Ed25519 challenge-response on every
  connection. `RegisterReq.claim.identity_pubkey` must equal the
  authenticated pubkey (no cross-binding). Second `Hello` on an
  authenticated connection is refused. Conflicts return
  `ControlMessage(USERNAME_TAKEN)` and close the connection.
- **1:1 voice + video calls.** Web client uses browser-native
  `RTCPeerConnection`; desktop uses GStreamer `webrtcbin`. Both speak
  Opus + VP8 + standard SDP/trickle ICE — they interoperate. Signaling
  tunneled through the existing Double Ratchet (SDP / ICE never
  plaintext to the relay or any TURN server).
- **SFrame** primitive layered on the web call's encoded-frame transform
  (Insertable Streams). Per-call base key derived via HKDF from the X3DH
  shared secret + a fresh `call_id`. Wire format matches
  `core/include/fb/media/sframe.hpp` so the desktop libwebrtc path will
  decrypt the same frames once it lands.
- **Login UI** on both clients — Create / Sign in / Recover-from-code
  panes, Argon2id derivation runs off the UI thread on desktop so the
  window doesn't freeze.
- **WebSocket transport** on the server (`--ws-port`) so browser clients
  connect natively. Per-frame masking + close handling per RFC 6455.
- **`--public` deployment flag** on the server. Binds to all interfaces
  and prints every reachable IPv4/IPv6 address with concrete `tcp:` /
  `ws://` URLs at the actual ports. `--help` ships a Caddyfile snippet
  for TLS-terminating reverse proxies.
- **WASM client** (~350 KB) with Discord-style HTML/CSS/JS UI. IndexedDB
  vault matches the desktop format byte-for-byte; recovery codes are
  paste-portable in either direction.
- **Persistence**: SQLite for chat history + channel state + offline
  queue + prekey directory. Survives a server restart with `--offline-db`.
- **P2P substrate** in `core/`: Kademlia DHT + gossipsub primitives;
  4-peer no-server demo passes (`tools/e2e/p2p_roundtrip.sh`).
- **Mesh bridge (serial)**: POSIX `termios` + brotli compression with a
  shared static dictionary, fits a typical chat line in one ~200-byte
  LoRa frame.
- **MQTT bridge**: Eclipse Paho C++ vendored under `third_party/`,
  round-trip tested against an embedded amqtt broker.

### Security pass
- **SenderKeys**: chain only advances on AEAD-success — a forged
  ciphertext at the receiver's current index no longer permanently
  desyncs from the next legitimate message. Same fix in the skipped-key
  cache path. Two regression tests added.
- **Web UI**: `[hidden]` attribute now actually hides modals + login
  panes (previously fought with element-specific `display: flex` rules).
- **Connect button**: in-flight guard against double-click WebSocket
  leaks. Sign-out hangs up live calls before tearing down the WS.
- **Inbound media signals**: per-peer FIFO so a fast-arriving ICE no
  longer races past the OFFER's CallSession installation.
- **`KeyBundleFetch`**: `request_id` correlation (oldest-first FIFO
  fallback) — concurrent fetches no longer cross-resolve.
- **Vault format**: KDF params bound into AEAD AAD; min/max bounds on
  `opslimit` / `memlimit` enforced at open to refuse downgrade and
  Argon2-OOM/hang attacks. `kdf_out` and the UTF-8 passphrase buffer
  zeroized on every exit path. Passphrase NFC-normalized so cross-IME
  inputs hash the same. `save_vault_file` uses `::rename(2)` + `fsync`
  for atomicity (was `QFile::remove` then `QFile::rename` — power-loss
  window left users with no vault).
- **Login**: cross-impl vault compatibility (web seal → desktop open)
  verified with a UTF-8 passphrase ("café") in a one-shot harness.

### Tests
- 86 native gtest cases across 18 suites.
- 9 web smokes (Node + WASM), including 2 adversarial security batteries
  (`auth_security_node.mjs`, `vault_security_node.mjs`).
- 7 end-to-end shell demos under `tools/e2e/`.

### Deferred (explicit non-goals for v1.0.1)
- **Group voice / video**: needs an SFU (mediasoup or Janus). Multi-week.
- **MLS group crypto** via mlspp: replaces SenderKeys at scale once the
  100k-LOC dependency is vendored. Multi-week.
- **Android client**: Kotlin/Compose + JNI scaffold is in place; needs
  NDK install + a real device or emulator.
- **iOS client**: scrapped — Linux dev environment can't compile or test.
- **In-server TLS**: deliberate deferral — front the server with a
  reverse proxy (caddy / nginx) instead. Standard practice for relay
  daemons (Postgres, Redis, MQTT brokers all do the same).

### License
- AGPL-3.0-or-later. SPDX headers on every source file.
