// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Linux epoll-based event loop. Single-threaded, callback-driven.
//
// This is a deliberate Phase-0 stand-in for what should eventually be Asio
// (cross-platform, mature). Asio is not present in the dev environment so we
// use raw epoll. The interface is intentionally small so swapping the backend
// later is mechanical.
//
// TODO(net-port): replace with standalone Asio when vcpkg/asio is available;
// move to QUIC (msquic) post-Phase-0 for the production network protocol.
// =============================================================================

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

namespace fb::net {

using FdReadyCallback = std::function<void(int fd, std::uint32_t events)>;
using TimerCallback   = std::function<void()>;

class IoLoop {
public:
    IoLoop();
    IoLoop(const IoLoop&)            = delete;
    IoLoop& operator=(const IoLoop&) = delete;
    ~IoLoop();

    // Register `fd` for `events` (EPOLLIN | EPOLLOUT | etc.). Replaces any
    // prior registration for the same fd.
    void add_fd(int fd, std::uint32_t events, FdReadyCallback cb);

    // Modify the events for an already-registered fd.
    void mod_fd(int fd, std::uint32_t events);

    // Remove (does not close) an fd from the loop.
    void remove_fd(int fd);

    // Schedule `cb` to fire once after `delay`. Backed by a single internal
    // timerfd and a min-heap of pending tasks.
    void schedule(std::chrono::milliseconds delay, TimerCallback cb);

    // Run until stop() is called. Blocks the thread.
    void run();
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::net
