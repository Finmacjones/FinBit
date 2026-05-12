# Windows port — status

Both `fb_server.exe` and `fb-cli.exe` build and pass `--help` smoke
tests on the `windows-latest` GitHub runner (MSVC 19.44, vcpkg
manifest, `win-msvc-release` CMake preset). Pre-built binaries
ship on the [Releases page](../../releases) as
`finbit-windows-x64.zip` alongside the Linux tarball.

## Build matrix

| Target                  | Linux x86_64 | Windows x64 (MSVC) | Web (WASM) |
|-------------------------|:------------:|:------------------:|:----------:|
| `core/` library         | ✅           | ✅                 | ✅         |
| `fb_server` (relay)     | ✅           | ✅                 | n/a        |
| `fb-cli` (text DM)      | ✅           | ✅                 | n/a        |
| `fb_desktop` (Qt6 + GStreamer) | ✅    | ⏳ v1.2+            | n/a        |
| WASM module             | ✅           | n/a                | ✅         |
| MLS feature (RFC 9420)  | ✅           | ⏳ (vendored mlspp port pending) | ✅ |
| Mesh bridge (LoRa serial) | ✅         | ⏳ (termios → DCB; deferred) | n/a |

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
| `core/src/mesh/serial_bridge.cpp` | `termios` | Not compiled on Windows (gated `if(NOT WIN32)` in `core/CMakeLists.txt`) |
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

- **`fb_desktop`** — Qt6 ports cleanly to Windows but the
  GStreamer/webrtcbin video stack needs Windows builds of GStreamer
  (multi-hour MSI wrangling) or a swap to native Win32 WebRTC
  (multi-week). v1.x ships server + CLI on Windows; desktop GUI is
  v1.2+.
- **Mesh bridge** — `termios` → Win32 DCB is real work for a
  feature most Windows desktops can't use (no LoRa radio attached).
  Stays off until there's demand.
- **MLS on Windows** — needs the vendored `mlspp` to build under
  MSVC + a `mls` vcpkg feature. Tracked.

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
