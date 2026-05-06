# FinBit

End-to-end encrypted, mesh-bridged, eventually-decentralized chat. Discord-style
UI, Signal-grade crypto, your own relay. **C++20** core compiled native (desktop
+ server) and to WebAssembly (browser). Voice + video over real WebRTC.

> **Status:** prototype. The cryptography uses well-vetted primitives
> (libsodium Ed25519 / X25519 / XChaCha20-Poly1305 / Argon2id, signal Double
> Ratchet, SenderKeys for groups), but the codebase as a whole has not had
> independent crypto review. Run it on a network you control; do not stake
> your physical safety on it yet.

|  | desktop (Qt6) | web (WASM) |
|---|---|---|
| Login dialog | <img src="docs/screenshots/desktop-login.png" width="320"/> | (similar — `client-web/ui/login_ui.js`) |
| Main UI | <img src="docs/screenshots/desktop-main.png" width="640"/> | Discord-style HTML/CSS/JS in `client-web/ui/` |

## What's real today

- **DMs** — Signal Double Ratchet over libsodium, AES-256-GCM (native) /
  XChaCha20-Poly1305 (WASM, no AES-NI). Server only ever sees ciphertext.
  86 native tests + 7 web smokes pass.
- **Channels** — SenderKeys group encryption. Per-(group, sender) symmetric
  chains with replay rejection, out-of-order delivery, post-eviction key
  invalidation. Invitees join via a `channel_key` DM payload.
- **Login** — Argon2id-protected identity vault on disk. v2 format binds
  KDF params into AEAD AAD (no downgrade), MODERATE tier (~256 MiB / ~1.5s
  per guess). Vault file is byte-identical between web and desktop.
- **Server-side username binding** — Ed25519 challenge-response on
  ClientHello + HelloAck. `RegisterReq` enforces claim-pubkey == auth-bound
  pubkey (no cross-binding). Second `Hello` on an authed connection is
  rejected. `USERNAME_TAKEN` `ControlMessage` on conflict.
- **Voice + video** — 1:1 WebRTC. Web uses browser-native
  `RTCPeerConnection`. Desktop uses GStreamer `webrtcbin`. Both speak
  Opus + VP8 + standard SDP/trickle ICE — they interop. Signaling tunneled
  through the existing Double Ratchet (SDP / ICE never plaintext to the
  relay or any TURN server).
- **Persistence** — SQLite (encrypted-at-rest planned). DMs, channels,
  prekey directory, offline queue all survive a server restart.
- **WebSocket transport** on the server (`--ws-port`) so browser clients
  connect natively.
- **P2P** — Kademlia DHT + gossipsub primitives in `core/`. fb-cli has
  `--p2p-create` / `--p2p-listen` modes; 4-peer no-server demo passes
  (`tools/e2e/p2p_roundtrip.sh`).
- **Mesh bridge (serial)** — POSIX `termios` + brotli, fits a typical
  chat line in one ~200-byte LoRa frame.
- **MQTT bridge** — Eclipse Paho C++ vendored under `third_party/`,
  round-trip tested with an embedded amqtt broker.

## What's still gated

| Subsystem | Blocker |
|---|---|
| MLS group crypto (replaces SenderKeys at scale) | mlspp not yet vendored |
| SFrame on top of WebRTC (matters once an SFU lands) | DTLS-SRTP is sufficient for current P2P |
| Group voice / video (SFU) | mediasoup or Janus integration |
| Android client | NDK not installed in this dev env (Kotlin/Compose scaffold ready) |

The full architectural plan (Phases 0–5, libwebrtc story, federation) lives
in `docs/architecture.md`. The wire protocol is in `docs/protocol-spec.md`.
The threat model (what FinBit defends against, what it doesn't) is in
`docs/threat-model.md`. What's intentionally not in v1.0.1 (group SFU, MLS,
Android, server-side TLS, etc.) is in `docs/ROADMAP.md` with effort
estimates and rationale.

---

## 5-minute quick start (Linux)

### 1. Install build prereqs

```bash
# Arch
sudo pacman -S cmake gcc libsodium sqlite protobuf fmt spdlog gtest \
               qt6-base brotli paho-mqtt-cpp gst-plugins-base gst-plugins-good \
               gst-plugins-bad gst-plugins-ugly

# Ubuntu 24.04
sudo apt install cmake build-essential libsodium-dev libsqlite3-dev \
                 libprotobuf-dev protobuf-compiler libfmt-dev libspdlog-dev \
                 libgtest-dev qt6-base-dev libbrotli-dev libpaho-mqttpp-dev \
                 libgstreamer1.0-dev libgstreamer-plugins-bad1.0-dev \
                 gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
                 gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly
```

### 2. Build

```bash
cmake -S . -B build/system
cmake --build build/system -j
ctest --test-dir build/system --output-on-failure   # 86 native tests
```

### 3. Run a local relay

```bash
build/system/server/fb_server --port 8765 --ws-port 8766 \
                              --offline-db /tmp/fb.db
```

You'll see:

```
[server] WS listening on 127.0.0.1:8766
[server] TCP listening on 127.0.0.1:8765
```

### 4. Open the desktop client

```bash
build/system/client-desktop/fb_desktop
```

The login dialog asks for a username + passphrase the first time; subsequent
runs sign you back in with the passphrase only. After signing in, leave the
host as `127.0.0.1` and click **Connect**.

### 5. Open the web client (optional)

```bash
# Build the WASM module — needs emsdk activated.
source ~/emsdk/emsdk_env.sh
scripts/build-wasm.sh

# Static dev server (Python 3 stdlib).
scripts/run-web-dev.sh
# → http://127.0.0.1:8080/ui/
```

In the browser, sign in with a passphrase, point the WS URL at
`ws://127.0.0.1:8766`, and click **Connect**.

### 6. Try a DM and a call

In two clients (any combination of desktop and web), claim distinct
usernames, click the other peer in the DM list, send a message, and click
**Call** or **Video**. You should hear / see each other.

---

## Going live (so others can connect)

Bind to all interfaces and let the server print every reachable URL:

```bash
build/system/server/fb_server --public --port 8765 --ws-port 8766 \
                              --offline-db /var/lib/fb.db
```

Output:

```
[server] WS listening on 0.0.0.0:8766
[server] TCP listening on 0.0.0.0:8765
[server] reachable at:
         tcp:  192.168.1.102:8765
         ws:   ws://192.168.1.102:8766
[server] NOTE: browsers refuse ws:// from https:// pages — for
         a public deployment, terminate TLS in a reverse proxy
         (caddy / nginx) and proxy wss:// to the ws-port above.
```

Open the firewall ports your cloud provider needs. A Caddyfile that
terminates TLS and forwards browser connections looks like:

```caddy
fb.example.com {
  reverse_proxy /ws  127.0.0.1:8766
}
```

`fb_server --help` has the full deployment cheat sheet.

---

## Testing

### Native tests

```bash
ctest --test-dir build/system --output-on-failure
```

Currently **86 tests** across 18 suites — crypto KAT, ratchet behaviour,
SenderKeys forge/replay rejection, P2P relay + dedup, server directory,
serial mesh round-trip, and more.

### Web smokes

Web smokes are Node.js scripts that drive the WASM module + a real
`fb_server` over WebSockets:

```bash
# Start the server in another terminal:
build/system/server/fb_server --port 8765 --ws-port 8766

cd client-web
NODE=~/emsdk/node/22.16.0_64bit/bin/node    # or your system node

$NODE test/wasm_roundtrip.js                # crypto self-test
$NODE test/wasm_channel_node.mjs            # SenderKeys (no server)
$NODE test/seal_seed_node.mjs               # vault round-trip
$NODE test/media_signal_node.mjs            # call signaling + SFrame
$NODE test/key_fetch_correlation_node.mjs   # request_id correlation
$NODE test/web_channel_node.mjs             # 2-client channel via server
$NODE test/username_takeover_node.mjs       # impostor rejection
$NODE test/auth_security_node.mjs           # 5 server-auth attacks
$NODE test/vault_security_node.mjs          # 9-offset tamper attack on vault
```

The two `*_security_node.mjs` smokes are the adversarial battery — they
mount tamper / replay / cross-bind / downgrade attacks and assert the
server / vault rejects them.

### End-to-end shell demos

Each spins up the necessary processes, runs a scripted exchange, and asserts
a randomized plaintext marker never appears in any relay's logs:

```bash
tools/e2e/dm_roundtrip.sh                       # 1:1 DM via Double Ratchet
tools/e2e/channel_inband_roundtrip.sh           # channel via DM-delivered SenderKeys
tools/e2e/p2p_roundtrip.sh                      # 4-peer P2P, no central server
tools/e2e/offline_persist.sh                    # queued DM survives restart
tools/e2e/server_persist_full.sh                # directory + prekeys + queue persist
tools/e2e/username_resolve.sh                   # pubkey → username resolution
tools/e2e/web_dm_roundtrip.sh                   # browser-style WebSocket DM
```

---

## Repo layout

```
core/                         shared C++20 library (crypto, proto, net,
                              p2p, media SFrame, mesh, store, ratelimit)
server/                       fb_server — single-process epoll relay
client-desktop/               fb_desktop — Qt6 client with login + calls
client-web/                   WASM module + Discord-style HTML/CSS/JS UI
client-mobile-android/        Kotlin/Compose scaffold (NDK pending)
tools/                        fb-cli, mesh-loopback, e2e shell demos
docs/                         architecture, protocol-spec, threat-model
scripts/                      build-wasm, build-libsodium-wasm,
                              build-paho, run-web-dev, etc.
```

Each `client-*/README.md` and `tools/*/README.md` has more detail on the
subsystem.

---

## Security model — brief

- **The server is a blind relay.** Every DM and channel message is opaque to
  it: the AEAD ciphertext, plus a recipient pubkey for routing, plus a
  sender pubkey for rate limiting.
- **Identity = Ed25519 keypair.** No usernames, no email — your fingerprint
  (a 10-char Crockford base32) is the durable identifier. Usernames are a
  display affordance the server enforces uniqueness on.
- **Login = unlock the at-rest vault.** Argon2id MODERATE tier (~256 MiB /
  ~1.5s) over XChaCha20-Poly1305. KDF params bound into AEAD AAD so the
  vault format itself can't be downgraded by a write-capable attacker. v1
  vaults (104 bytes, no AAD) still readable for migration.
- **Username binding is server-enforced.** Anyone with the public key can
  send messages claiming any username they like, but the server will only
  bind a username to one pubkey at a time — second client with a different
  pubkey gets a `USERNAME_TAKEN` `ControlMessage` and gets disconnected.
- **What's NOT protected (yet):** transport-layer confidentiality (no
  built-in TLS — front the server with a reverse proxy), metadata against
  the server (it sees who talks to whom and when, just not what), and
  forward secrecy of channel history (SenderKeys is forward-secret per
  message; the long-term escape valve is mlspp / RFC 9420 MLS).

Full threat model: `docs/threat-model.md`.

---

## Releases

Pre-built Linux x86_64 binaries are published on the
[Releases page](../../releases) in two flavours:

| Release | Updated | Stability |
|---|---|---|
| **`v1.x.x`** (tagged) | When a maintainer cuts a release | Stable — runs `ctest`, refuses to publish on failure |
| **`nightly`** | Every push to `main` | Bleeding-edge — same `ctest` gate, but no manual review |

Each tarball is `finbit-linux-x86_64*.tar.gz` with `bin/fb_server`,
`bin/fb_desktop`, `bin/fb-cli`, the LICENSE, README, CHANGELOG, ROADMAP
and a `RUNTIME_DEPS.md` apt/pacman cheat-sheet. A `.sha256` file
alongside lets you verify the download.

```bash
wget https://github.com/Finmacjones/finbit/releases/download/v1.0.1/finbit-linux-x86_64-v1.0.1.tar.gz
tar xzf finbit-linux-x86_64-v1.0.1.tar.gz
finbit-linux-x86_64-v1.0.1/bin/fb_server --help
```

### Cutting a new tagged release (maintainers)

```bash
# Bump the version in CHANGELOG.md, commit, then:
git tag v1.0.2
git push origin v1.0.2
```

The tag push triggers `.github/workflows/release.yml`, which builds the
full Linux release on a fresh Ubuntu 24.04 runner, runs `ctest`
(refuses to publish if anything fails), packages the three binaries +
docs into a tarball, and creates a GitHub Release with auto-generated
notes from the commit history since the previous tag. From v1.x
onward releases are marked as full releases (not pre-release); v0.x is
reserved for any pre-1.0 fixup tags should you ever need them.

### How the nightly works

Every push to `main` runs `.github/workflows/ci.yml` which builds, tests,
AND updates a single rolling release tagged `nightly`. Marked as
prerelease so it doesn't replace the most recent tagged `v*` release as
the "Latest" badge on the repo home page. The `nightly` tag always
points at the head of `main`; assets are replaced in place (no spam).

---

## Contributing

The cryptographic primitives in `core/crypto/` are the most sensitive part
of the codebase. Pull requests touching them should:

1. Add or extend a unit test in `core/tests/crypto/`
2. Run the full smoke battery (`ctest` + the `*_security_node.mjs` web
   smokes) and paste the output in the PR
3. Document any wire-format change in `docs/protocol-spec.md`

For everything else: a focused PR with a passing `ctest` is fine.

`docs/architecture.md` has the high-level design; `docs/protocol-spec.md`
has the wire format; `docs/threat-model.md` has the security boundaries
and known limitations.

---

## License

[**GNU Affero General Public License v3.0**](LICENSE) — same license Signal,
Element, and Matrix Synapse use.

The AGPL is "viral" in a way that matters here: anyone who runs a modified
FinBit server, even as a hosted SaaS where the modified binary is never
distributed, must publish their source. For an end-to-end-encrypted
messaging app whose security guarantee depends on what code is actually
running on the relay, that's the right default — users of a hosted FinBit
deployment can audit the server they're actually talking to, not just the
code in this repository.

If you want to use FinBit's crypto primitives (`core/crypto/`) under a
different license, open an issue — dual-licensing is on the table for
narrow, sensible cases.

---

## Acknowledgements

- libsodium for the cryptographic primitives
- Signal for the Double Ratchet + SenderKeys designs
- IETF MLS WG for the eventual group-crypto path (RFC 9420)
- Eclipse Paho for the MQTT bridge
- GStreamer for the desktop voice/video stack
- Discord for the UI conventions everyone now expects from a chat app
