# client-desktop

FinBit desktop client. Qt 6 / Widgets, links against `fb::core` directly.
Linux today; Windows / macOS need GStreamer install path tweaks but the
code is portable.

## What works

- **Login dialog** — passphrase-protected identity vault (Argon2id MODERATE
  + XChaCha20-Poly1305). Vault file format byte-identical to the web
  client. Argon2id derivation runs off the UI thread so the window stays
  responsive while the KDF is grinding.
- **Discord-style 3-column UI** — server rail, channels panel, chat area,
  rich message rows with avatars + timestamps.
- **DMs + channels** — full Phase 0/1 functionality through the relay.
  DM sessions are **post-quantum hybrid** (ML-KEM-768 ‖ X25519) when the
  build links OpenSSL 3.5+, with **sealed sender** hiding the sender pubkey
  from the relay once the session is PQ-acked.
- **1:1 voice + video** — GStreamer `webrtcbin` underneath. Opus + VP8;
  signaling via the existing Double Ratchet. Interoperates with the web
  client (both speak standard SDP/trickle ICE).
- **Identity verification** — a **Verify** button shows the per-peer safety
  number for out-of-band comparison; the verified state is persisted and a
  peer's pubkey changing mid-conversation raises a warning.
- **Social recovery** — an Identity-menu wizard splits your seed M-of-N
  (Shamir over GF(256)) and distributes shares to trusted contacts as DM
  payloads; the recovery wizard requests M shares back and rebuilds the
  vault.
- **Tor / SOCKS5** — set `FB_SOCKS=127.0.0.1:9050` to route through a local
  proxy with no DNS leak and per-peer Tor stream isolation.
- **Identity menu** — show recovery code (with confirm + clipboard), set up
  social recovery, sign out (closes connection, zeroes seed, returns to
  login).

## Build prereqs

```bash
# Arch
sudo pacman -S qt6-base qt6-tools libsodium sqlite \
               gstreamer gst-plugins-base gst-plugins-good \
               gst-plugins-bad gst-plugins-ugly

# Ubuntu 24.04
sudo apt install qt6-base-dev qt6-tools-dev libsodium-dev libsqlite3-dev \
                 libgstreamer1.0-dev libgstreamer-plugins-bad1.0-dev \
                 gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
                 gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly
```

## Build + run

```bash
# From repo root:
cmake -S . -B build/system
cmake --build build/system --target fb_desktop -j

build/system/client-desktop/fb_desktop
```

The first launch shows the LoginDialog. Create an identity (username +
passphrase), then in the main window leave host as `127.0.0.1` and click
Connect (assumes a local `fb_server` is running).

## Files

```
src/
  main.cpp                 launches LoginDialog → MainWindow
  main_window.{hpp,cpp}    Discord-style 3-column layout
  chat_client.{hpp,cpp}    QObject wrapping fb::core stack on a worker thread
  identity_vault.{hpp,cpp} Argon2id + XChaCha20 vault primitives (matches web)
  login_dialog.{hpp,cpp}   Create / Sign in / Recover panes
  verify_identity_dialog.{hpp,cpp}  safety-number compare + verified-status persist
  shamir_setup_wizard.{hpp,cpp}     Shamir social-recovery setup + recovery wizards
  bip39*.{hpp,cpp}         BIP39 recovery-phrase encode/decode + wordlist
  media_call.{hpp,cpp}     GStreamer webrtcbin wrapper
  room_forwarder.{hpp,cpp} voice-room mesh-dial / forwarder helper
  embedded_relay.hpp       optional in-process fb_server for solo testing
  message_delegate.{hpp,cpp}  rich message-row renderer
  avatar.{hpp,cpp}         FNV-1a-hue avatar generator
  crt_overlay.{hpp,cpp}    phosphor/CRT scanline + flicker effect overlay
  discord_theme.{hpp,cpp}  the QSS that gives us the dark Discord look
```

## Snapshot mode

For CI / docs:

```bash
QT_QPA_PLATFORM=offscreen FB_SNAPSHOT_LOGIN=/tmp/login.png \
  build/system/client-desktop/fb_desktop          # renders login dialog

QT_QPA_PLATFORM=offscreen FB_SNAPSHOT_NO_LOGIN=1 \
  FB_SNAPSHOT=/tmp/main.png \
  build/system/client-desktop/fb_desktop          # renders main window
                                                  # (uses dummy in-memory identity)
```

The screenshots in `docs/screenshots/` were made this way.

## Storage

User data lives at `$XDG_DATA_HOME/FinBit/FinBit/`:

```
<username>.vault   passphrase-protected seed (105-byte v2 blob)
<username>.db      SQLite — chat history, peer cache, channel state
```

The .vault file has 0600 perms; the parent dir 0700.
