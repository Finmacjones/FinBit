// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/tcp.hpp"

#if defined(_WIN32)
#  error "tcp.cpp uses POSIX sockets (arpa/inet, netinet/in, sys/socket). \
Windows port required: replace with Winsock2 (winsock2.h, ws2_32.lib). \
Tracked in docs/windows-port-status.md."
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace fb::net {

Socket::Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

Socket& Socket::operator=(Socket&& o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        o.fd_ = -1;
    }
    return *this;
}

Socket::~Socket() { close(); }

void Socket::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

void Socket::set_nonblocking() {
    const int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw std::runtime_error(std::string("F_SETFL O_NONBLOCK: ") + strerror(errno));
    }
}

void Socket::set_reuseaddr() {
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}

std::ptrdiff_t Socket::write_some(std::span<const std::uint8_t> data) {
    if (data.empty()) return 0;
    const ssize_t n = ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }
    return n;
}

std::ptrdiff_t Socket::read_some(std::span<std::uint8_t> out) {
    if (out.empty()) return kReadRetry;
    const ssize_t n = ::recv(fd_, out.data(), out.size(), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return kReadRetry;
        return -1;
    }
    return n;  // 0 = orderly EOF
}

Socket tcp_listen(const std::string& host, std::uint16_t port, int backlog) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error(std::string("socket: ") + strerror(errno));
    Socket s{fd};
    s.set_reuseaddr();
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (host == "0.0.0.0" || host.empty()) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (host == "127.0.0.1" || host == "localhost") {
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
            throw std::runtime_error("invalid bind host: " + host);
        }
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        throw std::runtime_error(std::string("bind: ") + strerror(errno));
    }
    if (::listen(fd, backlog) < 0) {
        throw std::runtime_error(std::string("listen: ") + strerror(errno));
    }
    return s;
}

Socket tcp_connect(const std::string& host, std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error(std::string("socket: ") + strerror(errno));
    Socket s{fd};
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (host == "127.0.0.1" || host == "localhost") {
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        // Try DNS.
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
            throw std::runtime_error("dns resolve failed: " + host);
        }
        sa.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        throw std::runtime_error(std::string("connect: ") + strerror(errno));
    }
    s.set_nonblocking();
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return s;
}

Socket tcp_accept(int listen_fd) {
    sockaddr_in sa{};
    socklen_t slen = sizeof(sa);
    int fd = ::accept4(listen_fd, reinterpret_cast<sockaddr*>(&sa), &slen,
                       SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return Socket{-1};
        throw std::runtime_error(std::string("accept4: ") + strerror(errno));
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return Socket{fd};
}

}  // namespace fb::net
