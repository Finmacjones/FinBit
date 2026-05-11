# Windows port — status

FinBit's first-class target today is Linux. Windows builds are stood up
in CI (`windows-latest` runner, MSVC, vcpkg) and run on every push to
`main` and on tagged releases. Until the POSIX-only files below have
Windows backends, the CI job is **expected to fail at compile** with
an `#error` directive pointing at the file that needs porting.

This document tracks the porting state — every PR that lights up one
of the files below should check it off here.

## Build matrix

| Target                  | Linux x86_64 | Windows x64 (MSVC) | Web (WASM) |
|-------------------------|:------------:|:------------------:|:----------:|
| `core/` library         | ✅           | ⏳ (port pending)   | ✅         |
| `fb_server` (relay)     | ✅           | ⏳                  | n/a        |
| `fb-cli` (text DM)      | ✅           | ⏳                  | n/a        |
| `fb_desktop` (Qt6 + GStreamer) | ✅    | ❌ deferred         | n/a        |
| WASM module             | ✅           | n/a                | ✅         |
| MLS feature (RFC 9420)  | ✅           | ⏳ (depends on core)| ✅         |
| Mesh bridge (LoRa)      | ✅           | ❌ deferred (termios)| n/a       |

✅ green  •  ⏳ pending (covered by an `#error` so CI tells you what to fix)  •  ❌ out of scope for v1.x

## Files with active `#error _WIN32` guards

| File | LOC | What's POSIX | Suggested Windows API |
|------|-----|--------------|----------------------|
| `core/src/net/io_loop.cpp` | 205 | `epoll_create1`, `epoll_ctl`, `epoll_wait`, `timerfd`, `pipe` | `WSAPoll` (simpler) **or** IOCP (faster); `CreateWaitableTimer` for timers; `CreateEvent` for the wake fd |
| `core/src/net/tcp.cpp` | 141 | `sys/socket`, `arpa/inet`, `netdb`, `netinet/tcp` | Winsock2 (`winsock2.h`, `ws2_32.lib`), `WSAStartup` at process init, `closesocket` instead of `close`, `WSAGetLastError` instead of `errno` |
| `core/src/net/tls_client.cpp` | 371 | POSIX `select()` driving OpenSSL handshake | Same OpenSSL API works on Windows; replace `select` with `WSAPoll`. Alternatively switch to BIO-pair (no FD-level polling needed). |
| `core/src/p2p/gossip.cpp` | 450 | `sys/epoll` directly | Factor the epoll calls behind `fb::net::IoLoop` (which is already the shared abstraction). Once `io_loop.cpp` ports, `gossip.cpp` ports for free. |
| `core/src/p2p/peer_net.cpp` | 619 | POSIX sockets + `select()` | Depends on `tcp.cpp` and `tls_client.cpp` being ported first. |
| `core/src/mesh/serial_bridge.cpp` | 200 | `termios`, `sys/select` | `CreateFile("\\\\.\\COM1", ...)` + `DCB` + `COMMTIMEOUTS`. **Or**: leave mesh OFF by default for the Windows target (current behaviour — `FB_BUILD_MESH=OFF` in `win-msvc-release` preset). |
| `server/src/main.cpp` | 1121 | `epoll` directly, `getifaddrs`, `signal()` | Factor accept loop behind `fb::net::IoLoop`; replace `getifaddrs` with `GetAdaptersAddresses`; replace `signal(SIGINT)` with `SetConsoleCtrlHandler`. |

**Total: ~3,107 LOC of porting work**, structured so the ports can land independently:

1. `io_loop.cpp` first (foundation — gossip.cpp inherits its Windows path).
2. `tcp.cpp` second (foundation — `tls_client.cpp` and `peer_net.cpp` need it).
3. `tls_client.cpp` third.
4. `peer_net.cpp` fourth.
5. `server/main.cpp` fifth (refactor to use IoLoop).
6. `gossip.cpp` should be a no-op once `io_loop.cpp` is done.
7. `serial_bridge.cpp` last (mesh is opt-in; can stay OFF on Windows for v1.0).

## How to make CI green incrementally

Each PR that ports one file should:

1. Drop the file-scope `#if defined(_WIN32) #error "..." #endif` block at the top.
2. Add `#ifdef _WIN32` branches around the platform-specific calls inside the file.
3. Push — CI surfaces the next file's error.

Once all listed files are ported, flip `continue-on-error: true` to `false`
in `.github/workflows/build-windows.yml` so future regressions block
the merge.

## What's deferred to a later release

- **`fb_desktop`** — Qt6 ports cleanly to Windows, but the GStreamer
  webrtcbin video stack requires Windows builds of GStreamer
  (~few hours of MSI installer wrangling) **or** swapping in native
  Win32 WebRTC (multi-week). v1.x ships server + CLI on Windows; the
  desktop GUI is a v1.2+ target.
- **Mesh bridge** — `termios` → Win32 serial is real work for a feature
  most Windows desktops can't even use (no LoRa radio attached). Stays
  off until there's user demand.

## What's already cross-platform

- The full **WASM** build (`scripts/build-wasm.sh`) runs unchanged on
  Linux or Windows hosts via emsdk; the resulting `finbit.mjs` is
  portable to any browser or Node.js.
- All of **`core/src/crypto/`**, **`core/src/store/`**, **`core/src/identity/`**
  are pure C++ + libsodium + sqlite3 (no POSIX-specific calls). They
  compile on Windows today; the linker-time failure is purely from the
  net/p2p/mesh layers above.
