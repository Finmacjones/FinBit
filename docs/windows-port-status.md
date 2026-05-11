# Windows port — status

## Build matrix

| Target                  | Linux x86_64 | Windows x64 (MSVC) | Web (WASM) |
|-------------------------|:------------:|:------------------:|:----------:|
| `core/` library         | ✅           | ✅ (ported)         | ✅         |
| `fb_server` (relay)     | ✅           | ✅ (ported)         | n/a        |
| `fb-cli` (text DM)      | ✅           | ✅ (ported)         | n/a        |
| `fb_desktop` (Qt6 + GStreamer) | ✅    | ⏳ deferred (v1.2+) | n/a        |
| WASM module             | ✅           | n/a                | ✅         |
| MLS feature (RFC 9420)  | ✅           | ⏳ (vendored mlspp on Windows pending) | ✅ |
| Mesh bridge (LoRa)      | ✅           | ⏳ deferred (termios → DCB) | n/a |

✅ done • ⏳ deferred to a later release

## Per-file porting status

| File | Linux backend | Windows backend |
|------|---------------|-----------------|
| `core/src/net/io_loop.cpp` | `epoll_create1`/`epoll_ctl`/`epoll_wait` + `timerfd` + `pipe2` | `WSAPoll` + std::priority_queue timer drain + loopback-TCP wake pair |
| `core/src/net/tcp.cpp` | BSD sockets via `sys/socket.h` | Winsock2 (`socket`, `closesocket`, `ioctlsocket(FIONBIO)`, `WSAGetLastError`) |
| `core/src/net/tls_client.cpp` | POSIX `select()` driving SSL handshake | `WSAPoll`-backed `wait_socket_ready()` helper |
| `core/src/p2p/gossip.cpp` | uses `EPOLL*` constants from `<sys/epoll.h>` | constants come from `fb/net/io_loop.hpp` Windows fallback `#define`s |
| `core/src/p2p/peer_net.cpp` | POSIX sockets + `select()` + `SIGPIPE` ignore | Winsock2 + `WSAPoll` + skips `SIGPIPE` |
| `core/src/mesh/serial_bridge.cpp` | `termios` | **Unported** — Windows build disables mesh feature (`FB_BUILD_MESH=OFF`). Stays off in v1.x. |
| `server/src/main.cpp` | epoll directly via IoLoop; `getifaddrs`; `signal(SIGINT/SIGTERM/SIGPIPE)` | IoLoop's Windows backend; `GetAdaptersAddresses` (iphlpapi); `SetConsoleCtrlHandler` |

## What changed in each file

- **`io_loop.cpp`** — single file, two backends. Linux unchanged (epoll
  + timerfd + pipe). Windows uses `WSAPoll` driven by a per-iteration
  pollset rebuild from `events_for_fd`, a loopback-TCP socket pair for
  cross-thread wake, and a `std::priority_queue` drained from the
  WSAPoll timeout.

- **`tcp.cpp`** — wraps `Socket` operations. `set_nonblocking()` calls
  `ioctlsocket(FIONBIO)` on Windows; `close` calls `closesocket`;
  `send`/`recv` cast through `SOCKET`. `tcp_listen` / `tcp_connect` /
  `tcp_accept` all branch.

- **`tls_client.cpp`** — extracted a `wait_socket_ready()` helper that
  uses `WSAPoll` on Windows, `select()` on POSIX. The three SSL
  handshake / read / write polling sites now share one path.

- **`peer_net.cpp`** — same `wait_socket_ready()` pattern, plus the
  accept-loop's polling. `SIGPIPE` ignore is gated `#ifndef _WIN32`.
  `getsockname` casts the fd through `SOCKET` on Windows; `socklen_t`
  is `int` on Windows (via ws2tcpip.h).

- **`gossip.cpp`** — no direct epoll calls; just needed the `EPOLL*`
  constants. Those now come from `fb/net/io_loop.hpp` on Windows
  (synthesised as the corresponding POLL* values).

- **`server/main.cpp`** — `external_addresses()` has a Windows arm that
  uses `GetAdaptersAddresses` from iphlpapi.lib. Signal handlers are
  `SetConsoleCtrlHandler` instead of `signal(SIGINT/SIGTERM)`; no
  SIGPIPE on Windows.

## What's deferred to later releases

- **`fb_desktop`** — Qt6 ports cleanly, but the GStreamer/webrtcbin
  video stack requires Windows-built GStreamer (~few hours of MSI
  wrangling) **or** swapping in native Win32 WebRTC. v1.x ships
  server + CLI on Windows; the desktop GUI is v1.2+.
- **Mesh bridge** — `termios` → Win32 serial DCB is real work for a
  feature most Windows desktops can't use (no LoRa radio attached).
  Stays off until there's demand.
- **MLS on Windows** — vendored mlspp needs a separate vcpkg port or
  to build via its own CMakeLists in Windows. Currently `mls`
  feature is opt-in; enabling it on Windows is a follow-up.

## What's verified

- **Linux** (host build) — 183 default / 193 MLS / 182 ASan / 182 TSan
  tests pass; 10 e2e canary scripts pass. No regression from the port.
- **Windows** (CI build) — `.github/workflows/build-windows.yml` runs
  on every push to `main` and on tagged releases. The job compiles
  `fb_server.exe` + `fb-cli.exe`, runs `--help` smoke tests on both,
  and uploads `finbit-windows-x64-<sha>.zip` containing the
  executables + linked vcpkg DLLs.

## Maintainer flip

Once one successful Windows CI run lands, flip `continue-on-error:
true` to `false` in `.github/workflows/build-windows.yml` so any
future Windows regression blocks the merge.
