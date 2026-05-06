# client-web

Browser-resident FinBit client. Compiles `core/` to WebAssembly via
Emscripten, drives a Discord-style HTML/CSS/JS UI on top.

## What works

- **Identity vault** — Argon2id-protected (MODERATE tier) Ed25519 seed
  stored in IndexedDB. v2 format binds KDF params into AEAD AAD.
- **DMs via Double Ratchet** — XChaCha20-Poly1305 (no AES-NI in WASM).
- **Channels via SenderKeys** — invitees join via a `channel_key` DM.
- **1:1 voice + video** — browser-native `RTCPeerConnection`, signaling
  tunneled through the existing ratchet, SFrame layered on top via
  Insertable Streams (Chromium-only — Firefox falls back to DTLS-SRTP
  with a console warning).
- **Recovery code** — 64-char hex of the seed; portable to/from the
  desktop client.

## Layout

```
ui/             Discord-style HTML/CSS/JS — load via a static dev server
wasm-shim/      C++ embind shim that compiles to finbit.{js,mjs,wasm}
build/          generated; not tracked
test/           9 Node smokes (run via `~/emsdk/node/.../node`)
```

## Build the WASM module

```bash
# Activate emsdk (fetch via https://emscripten.org if not installed)
source ~/emsdk/emsdk_env.sh

# Build libsodium for WASM (one-time, ~3 min)
scripts/build-libsodium-wasm.sh

# Build the protobuf runtime for WASM (one-time)
scripts/build-protobuf-wasm.sh

# Build the FinBit WASM module (~30 s incremental)
scripts/build-wasm.sh
```

Output: `client-web/build/finbit.{js,mjs,wasm}` (~350 KB total).

## Run

```bash
# In one terminal: relay
build/system/server/fb_server --port 8765 --ws-port 8766

# In another: static file server for the UI
scripts/run-web-dev.sh        # → http://127.0.0.1:8080/ui/
```

Open the URL, sign in (creates a vault first time), point the WS field at
`ws://127.0.0.1:8766`, click Connect.

## Tests

All Node smokes (run with `~/emsdk/node/22.16.0_64bit/bin/node`):

| File | Needs server? | What it checks |
|---|---|---|
| `wasm_roundtrip.js` | no | XChaCha20 AEAD round-trip + tamper |
| `wasm_channel_node.mjs` | no | SenderKeys group encrypt/decrypt |
| `seal_seed_node.mjs` | no | vault seal/open round-trip |
| `media_signal_node.mjs` | no | call signaling proto + SFrame |
| `key_fetch_correlation_node.mjs` | no | request_id correlation |
| `web_channel_node.mjs` | yes | 2-client channel via WebSocket |
| `username_takeover_node.mjs` | yes | server rejects impostor |
| `auth_security_node.mjs` | yes | 5 server-auth attacks |
| `vault_security_node.mjs` | no | 9-offset tamper attack on vault |

The two `*_security_node.mjs` smokes are the adversarial battery.

## Constraints

The browser cannot do raw UDP, cannot run a P2P node well, cannot keep a
background socket alive when the tab closes, and cannot speak USB serial.
So the web client:

- Always uses the centralized relay (no P2P fan-out from a tab)
- Cannot be a mesh-bridge gateway (no serial)
- Voice/video is P2P with STUN; SFU/group calls deferred until that lands
- Push notifications via the browser's Push API (server delivers opaque
  ciphertext blobs; the service worker decrypts on receipt) — not yet wired

## Bundle size

`finbit.wasm` is ~350 KB. The full UI bundle (HTML+CSS+JS+WASM) is well
under the 10 MB compressed budget the original plan called for.
