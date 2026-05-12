# Windows port — status

Both `fb_server.exe` and `fb-cli.exe` build and pass `--help` smoke
tests on the `windows-latest` GitHub runner (MSVC 19.44, vcpkg
manifest, `win-msvc-release` CMake preset). Pre-built binaries
ship on the [Releases page](../../releases) as
`finbit-windows-x64.zip` alongside the Linux tarball.

## Functional parity matrix (per ship-blocking feature)

What's actually reachable from each shipped binary, after the port:

| Feature | Linux `fb_desktop` | Linux `fb-cli` | Linux `fb_server` | Windows `fb-cli.exe` | Windows `fb_server.exe` |
|---|:--:|:--:|:--:|:--:|:--:|
| 1:1 DM via Double Ratchet (text) | ✅ | ✅ | ✅ relay | ✅ | ✅ relay |
| Channels via SenderKeys (text) | ✅ | ✅ | ✅ relay | ✅ | ✅ relay |
| MLS-encrypted channels (RFC 9420) | ✅ (`FB_FEATURE_MLS=ON`) | ✅ (same) | ✅ relay | ⏳ in CI (`build-windows-mls.yml`) | ⏳ same |
| Username log + DHT prekey publish | ✅ | ✅ | n/a | ✅ | n/a |
| PeerNet direct P2P (mTLS) | ✅ | ✅ | n/a | ✅ | n/a |
| Friend-relay offline store | ✅ | ✅ | n/a | ✅ | n/a |
| WSS / TLS relay transport | ✅ | ✅ (`--tls`) | ✅ (`--tls-raw-port` / `--tls-port`) | ✅ | ✅ |
| Per-row AEAD SQLite store | ✅ | n/a (in-memory) | ✅ (offline queue + directory + prekeys) | n/a | ✅ |
| Identity vault on disk (Argon2id-v2) | ✅ | n/a (ephemeral keypair) | n/a | n/a | n/a |
| 1:1 voice / video (WebRTC) | ✅ (GStreamer) | n/a | ✅ signaling fan-out | ❌ (no `fb_desktop`) | ✅ signaling fan-out |
| Full-mesh channel voice | ✅ | n/a | ✅ `RoomJoin/RoomRoster` | ❌ | ✅ |
| Mesh bridge (MQTT) | ✅ (`paho-mqttpp3` feature) | n/a | n/a | ✅ (paho-mqttpp3 x64-windows triplet) | ✅ |
| Mesh bridge (LoRa serial) | ✅ termios | n/a | n/a | ✅ Win32 `CreateFile` + DCB | ✅ |
| Anti-DoS token bucket | ✅ | n/a | ✅ | n/a | ✅ |
| Server-blindness (canary asserts) | ✅ 10 e2e | ✅ same | ✅ same | ✅ `dm_roundtrip.ps1` | ✅ same |

✅ shipped • ⏳ deferred • ❌ out of scope for v1.x

### What this means for users picking a target

- **Linux x86_64** — full stack: desktop GUI, voice + video, mesh
  bridge, MLS. Use this for end-user installs and for running a
  production relay.
- **Windows x64** — server + CLI only at v1.0. Sufficient for
  hosting a relay on a Windows VPS, scripting / automation via
  `fb-cli.exe`, and Windows-side CI / build tooling. End-user GUI
  is v1.2+ (Qt6 + GStreamer needs Windows-built GStreamer or a
  swap to Win32 WebRTC).
- **Web (WASM)** — full DM / channel / 1:1-call client; runs in any
  modern browser including Windows ones, so Windows users who want
  the GUI today have a working path via `https://`.

### CI coverage per target

| Test surface | Linux | Windows |
|---|:--:|:--:|
| `ctest` default (183 tests) | ✅ every push | ❌ (`FB_BUILD_TESTS=OFF` on Windows preset) |
| `ctest` MLS (193 tests) | ✅ on tagged release | ❌ same |
| ASan + UBSan (182 tests) | ✅ nightly | ❌ (sanitisers Linux-only) |
| TSan (182 tests) | ✅ nightly | ❌ same |
| `tools/e2e/*.sh` canary suite (10 scripts) | ✅ every push | ➜ `tools/e2e/dm_roundtrip.ps1` (1 script, same canary property) |
| `--help` smoke | ✅ | ✅ |
| Published binary verification (sha256) | ✅ | ✅ |

The Windows runtime test footprint is intentionally smaller than
Linux's — the Linux box hosts the sanitiser variants and the full
e2e shell suite, while Windows CI runs the compile + smoke + one
canary-asserting DM round-trip. If the Windows binaries had a
regression that the unit tests couldn't catch (e.g. a `WSAPoll`
behavioural difference), the `dm_roundtrip.ps1` failure surfaces it.

## Build matrix

| Target                  | Linux x86_64 | Windows x64 (MSVC) | Web (WASM) |
|-------------------------|:------------:|:------------------:|:----------:|
| `core/` library         | ✅           | ✅                 | ✅         |
| `fb_server` (relay)     | ✅           | ✅                 | n/a        |
| `fb-cli` (text DM)      | ✅           | ✅                 | n/a        |
| `fb_desktop` (Qt6 + GStreamer) | ✅    | ⏳ in CI (build-windows-desktop.yml) | n/a |
| WASM module             | ✅           | n/a                | ✅         |
| MLS feature (RFC 9420)  | ✅           | ⏳ in CI (build-windows-mls.yml; continue-on-error) | ✅ |
| Mesh bridge (LoRa serial) | ✅         | ✅ (Win32 CreateFile + DCB; this release) | n/a |

✅ shipped • ⏳ deferred to a later release

## Per-file porting summary

Every POSIX-only file has a Windows backend behind `#ifdef _WIN32`.
Linux paths are byte-identical to before the port; Windows builds
take the alternate branch.

| File | Linux backend | Windows backend |
|------|---------------|-----------------|
| `core/src/net/io_loop.cpp` | `epoll` + `timerfd` + `pipe2` | `WSAPoll` + `priority_queue` timer drain + peer-pinned loopback-TCP wake pair |
| `core/src/net/tcp.cpp` | BSD sockets | Winsock2 (`closesocket`, `ioctlsocket(FIONBIO)`, `WSAGetLastError`) |
| `core/src/net/tls_client.cpp` | `select()` driving SSL | `WSAPoll`-backed `wait_socket_ready()` |
| `core/src/p2p/gossip.cpp` | `EPOLL*` from `<sys/epoll.h>` | constants come from `fb/net/io_loop.hpp` synth `#define`s |
| `core/src/p2p/peer_net.cpp` | POSIX sockets + `select()` + `SIGPIPE` ignore | Winsock2 + `WSAPoll` + no-SIGPIPE; `shutdown` uses `SD_BOTH` |
| `core/src/mesh/serial_bridge.cpp` | `termios` + `select()` | `CreateFileA("\\\\.\\COMx")` + DCB + `SetCommTimeouts` (100ms read window matches POSIX poll) + `ReadFile`/`WriteFile` |
| `server/src/main.cpp` | epoll via IoLoop + `getifaddrs` + `signal()` | IoLoop Windows backend + `GetAdaptersAddresses` + `SetConsoleCtrlHandler` |
| `tools/fb-cli/main.cpp` | `select()` + `signal()` + `MSG_NOSIGNAL` send | `WSAPoll` + `SetConsoleCtrlHandler` + Winsock send |

## CMake / vcpkg

- `CMakePresets.json` defines `win-msvc-release` — Visual Studio 17
  2022 generator, x64 architecture, vcpkg toolchain, `x64-windows`
  triplet, `FB_BUILD_DESKTOP_CLIENT=OFF`, `FB_BUILD_TESTS=OFF`.
- `vcpkg.json` Windows manifest features pull: `libsodium`,
  `protobuf`, `sqlite3`, `brotli`, plus `openssl` + `zlib` from the
  `server` feature. Test/bench deps live behind `tests`/`bench`
  features which are off for the Windows server build.
- Top-level CMakeLists defines `NOMINMAX` + `_CRT_SECURE_NO_WARNINGS`
  for the MSVC arm.

## What's not in v1.x

- **`fb_desktop`** — Build pipeline lives in
  `build-windows-desktop.yml` (Qt6 via the `jurplel/install-qt-action`,
  GStreamer via Chocolatey's MSI). Build is `continue-on-error`
  until one green CI run lands. When it does, `windeployqt` bundles
  the Qt plugins and `finbit-windows-x64-desktop.zip` ships
  alongside the server bundle. Linux remains the canonical desktop
  target while the Windows GUI matures.
- **MLS on Windows** — `scripts/fetch-mlspp.ps1` clones
  cisco/mlspp into `third_party/` on the runner; CMake then
  `add_subdirectory`s it via the `win-msvc-release-mls` preset
  (FB_FEATURE_MLS=ON). MSVC warning-as-error flags from mlspp's
  own CMakeLists get stripped via `/W3 /WX-` in the top-level
  CMakeLists' MLS branch. Workflow is `continue-on-error: true`
  while the build stabilises — flip after one green run, same
  pattern as the server/CLI Windows port went through.

## Security parity

Both targets covered by `docs/pentest-report.md`. The
post-Windows-port pass added test coverage for:

- The peer-pinned wake-pair race fix (F7) in `io_loop.cpp`.
- Cross-platform `wait_socket_ready()` semantics in `tls_client.cpp`
  and `peer_net.cpp`.
- Re-run wire / heap / fuzzer / sanitiser canaries on Linux —
  zero regressions from the port.

Linux sanitiser builds (ASan, TSan) and the full e2e suite remain
the canonical security gate; Windows CI runs the compile + smoke
stages only (no host-side sanitisers in CI yet).
