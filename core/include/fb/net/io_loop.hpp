// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Cross-platform event loop. Single-threaded, callback-driven.
//
// Linux:   backed by epoll + timerfd.
// Windows: backed by WSAPoll + std::priority_queue timer drain.
//
// The two backends share the same API. EPOLLIN / EPOLLOUT / EPOLLERR /
// EPOLLHUP / EPOLLET constants are wired through to the right kernel
// primitives on each platform (EPOLLET becomes a no-op on Windows
// because WSAPoll is level-triggered; callers can pass it harmlessly).
//
// TODO(net-port): replace with standalone Asio when vcpkg/asio is
// available; move to QUIC (msquic) post-Phase-0.
// =============================================================================

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

#if defined(_WIN32)
// On Linux, sys/epoll.h provides EPOLLIN / EPOLLOUT etc.; callers
// pick them up by including <sys/epoll.h> themselves before this
// header. On Windows we synthesize the same constants so the same
// caller code compiles unchanged. The values mirror POLLIN /
// POLLOUT / etc. so a Windows-backed WSAPoll can pass them
// through directly.
#  ifndef EPOLLIN
#    define EPOLLIN     0x0001
#  endif
#  ifndef EPOLLOUT
#    define EPOLLOUT    0x0004
#  endif
#  ifndef EPOLLERR
#    define EPOLLERR    0x0008
#  endif
#  ifndef EPOLLHUP
#    define EPOLLHUP    0x0010
#  endif
#  ifndef EPOLLRDHUP
#    define EPOLLRDHUP  0x2000
#  endif
#  ifndef EPOLLET
#    define EPOLLET     0   // WSAPoll is level-triggered; flag ignored
#  endif
#endif

namespace fb::net {

using FdReadyCallback = std::function<void(int fd, std::uint32_t events)>;
using TimerCallback   = std::function<void()>;

class IoLoop {
public:
    IoLoop();
    IoLoop(const IoLoop&)            = delete;
    IoLoop& operator=(const IoLoop&) = delete;
    ~IoLoop();

    // Register `fd` (a TCP socket descriptor on Linux, a Winsock
    // SOCKET narrowed to int on Windows) for `events` (EPOLLIN |
    // EPOLLOUT | etc.). Replaces any prior registration for the
    // same fd.
    void add_fd(int fd, std::uint32_t events, FdReadyCallback cb);

    // Modify the events for an already-registered fd.
    void mod_fd(int fd, std::uint32_t events);

    // Remove (does not close) an fd from the loop.
    void remove_fd(int fd);

    // Schedule `cb` to fire once after `delay`. Linux uses an
    // internal timerfd; Windows uses a std::priority_queue drained
    // from the WSAPoll timeout.
    void schedule(std::chrono::milliseconds delay, TimerCallback cb);

    // Run until stop() is called. Blocks the thread.
    void run();
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::net
