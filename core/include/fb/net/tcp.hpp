// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Thin TCP socket wrappers around POSIX. Non-blocking, used with IoLoop.
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace fb::net {

class Socket {
public:
    Socket() noexcept = default;
    explicit Socket(int fd) noexcept : fd_(fd) {}
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& o) noexcept;
    Socket& operator=(Socket&& o) noexcept;
    ~Socket();

    [[nodiscard]] int fd() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    int release() noexcept {
        const int f = fd_;
        fd_ = -1;
        return f;
    }
    void close();

    // Set O_NONBLOCK and SO_REUSEADDR on this socket.
    void set_nonblocking();
    void set_reuseaddr();

    // Non-blocking write. Returns bytes actually written (may be 0 on EAGAIN
    // or short). Negative on error other than EAGAIN.
    std::ptrdiff_t write_some(std::span<const std::uint8_t> data);

    // Non-blocking read. Return values:
    //   > 0 : bytes read into `out`
    //     0 : EOF — peer has cleanly closed the connection
    //   kReadRetry (-2) : EAGAIN / EWOULDBLOCK — try again later
    //    -1 : permanent error
    static constexpr std::ptrdiff_t kReadRetry = -2;
    std::ptrdiff_t read_some(std::span<std::uint8_t> out);

private:
    int fd_ = -1;
};

// Helpers for creating listeners and outbound connections. These return ready-to-use
// non-blocking sockets registered NOWHERE (caller registers with IoLoop).
[[nodiscard]] Socket tcp_listen(const std::string& host, std::uint16_t port, int backlog = 64);
[[nodiscard]] Socket tcp_connect(const std::string& host, std::uint16_t port);
[[nodiscard]] Socket tcp_accept(int listen_fd);

}  // namespace fb::net
