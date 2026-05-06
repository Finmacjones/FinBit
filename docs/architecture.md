# FinBit architecture

Top-level orientation. For wire-format details see
[`protocol-spec.md`](protocol-spec.md); for the security boundaries see
[`threat-model.md`](threat-model.md); for deployment notes see
[`ops-runbook.md`](ops-runbook.md); for what's intentionally not in
v1.0.1 see [`ROADMAP.md`](ROADMAP.md).

## Layout

```
finbit/
├── core/                # shared C++20 library, namespace fb::
│   ├── include/fb/{config,crypto,model,net,store,ratelimit,
│   │             media,mesh,p2p,sync,reputation,util}/
│   ├── src/             # mirrors include/
│   ├── proto/           # *.proto -> generated C++ at build time
│   └── tests/           # gtest
├── server/              # epoll relay daemon
├── client-desktop/      # Qt 6 / QML  (Phase 1)
├── client-web/          # Emscripten + Svelte (Phase 1+)
├── client-mobile-android/   # Kotlin Compose + JNI (Phase 1+)
├── tools/{fb-cli,e2e,mesh-loopback}/
└── docs/
```

## What's real today (Phase 0)

| Subsystem        | State |
|------------------|-------|
| Build system     | CMake + vcpkg manifest, system-pkg-config fallback |
| Ed25519 identity | Real (libsodium); KAT + sign/verify tested |
| AES-256-GCM AEAD | Real; NIST/McGrew Test Case 16 KAT passes |
| Double Ratchet   | Real (libsodium HKDF + X25519 + HMAC-SHA256); 9 behaviour tests pass |
| Wire protocol    | Envelope, Frame, RatchetMessage, PreKeyBundle, ClientHello, KeyBundle ops |
| Network layer    | epoll loop + non-blocking TCP + length-prefixed framing |
| Storage          | SQLite-backed identity / peer-keys / sessions / inbox / outbox / carry-ledger |
| Rate limit       | Per-pubkey token bucket; tested |
| Server           | Blind relay with register/keybundle/relay/offline-queue + rate limit |
| fb-cli           | Two-mode (send/listen) demo client driving the full stack |
| End-to-end test  | `tools/e2e/dm_roundtrip.sh` — random-marker server-blindness assertion |

## What's scaffolded (Phase 1+)

| Subsystem        | Phase | Header / location | Blocker |
|------------------|-------|-------------------|---------|
| MLS group crypto | 1     | `core/include/fb/crypto/mls_facade.hpp` | mlspp dep |
| Channel models   | 1     | `core/include/fb/model/types.hpp` | uses MLS |
| WebRTC media     | 2/3   | `core/include/fb/media/peer_connection.hpp` | libwebrtc dep |
| MQTT mesh bridge | 4     | `core/include/fb/mesh/bridge.hpp` | Paho MQTT dep |
| Serial mesh bridge | 4   | `core/include/fb/mesh/bridge.hpp` | Meshtastic protobuf schema |
| P2P substrate    | 5     | `core/include/fb/p2p/host.hpp` | cpp-libp2p or libtorrent-DHT dep |
| Desktop UI       | 1+    | `client-desktop/` | Qt 6 |
| Web UI           | 1+    | `client-web/` | Emscripten |
| Mobile UIs       | 1+    | `client-mobile-{android,ios}/` | Android NDK / Xcode |

Every scaffold throws `std::runtime_error("... not implemented (Phase X
— needs DEPENDENCY)")` so attempts to use the API at runtime fail loudly
rather than silently producing wrong results.

## The placeholder server URL

Lives in `core/include/fb/config/build_config.hpp` as
`fb::config::kDefaultServerUrl`. Single grep to find/swap. Runtime
overridable via `FB_SERVER_URL` env var (Phase 1 wires the override into
the client startup path).

## Verification

```bash
cmake -S . -B build/system
cmake --build build/system -j
ctest --test-dir build/system --output-on-failure
tools/e2e/dm_roundtrip.sh
```

35+ unit tests + 1 end-to-end script. Crypto tests use NIST/IETF
test vectors where they exist; Double Ratchet behaviour is covered by
self-consistent transcript tests pending Phase 1 integration with
`libsignal-protocol-c` cross-vector tests.
