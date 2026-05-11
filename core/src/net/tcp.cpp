// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/tcp.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "Ws2_32.lib")
   // No MSG_NOSIGNAL on Windows (no SIGPIPE — closed sockets return
   // WSAESHUTDOWN). Map to 0 so send() compiles cleanly.
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace fb::net {

#if defined(_WIN32)
namespace {
// Idempotent WSAStartup. Each call increments Winsock's refcount; we
// only ever take one ref process-wide via this static. Matches the
// pattern in io_loop.cpp.
struct WinsockInit {
    WinsockInit() {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error(
                "WSAStartup failed: " +
                std::to_string(WSAGetLastError()));
        }
    }
    ~WinsockInit() { WSACleanup(); }
};
WinsockInit& ensure_winsock() {
    static WinsockInit one;
    return one;
}
std::string last_err_str(const char* op) {
    return std::string(op) + ": WSA error " +
           std::to_string(WSAGetLastError());
}
}  // namespace
#else
namespace {
std::string last_err_str(const char* op) {
    return std::string(op) + ": " + strerror(errno);
}
}  // namespace
#endif

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
#if defined(_WIN32)
        ::closesocket(static_cast<SOCKET>(static_cast<std::uintptr_t>(fd_)));
#else
        ::close(fd_);
#endif
        fd_ = -1;
    }
}

void Socket::set_nonblocking() {
#if defined(_WIN32)
    u_long nbio = 1;
    if (::ioctlsocket(static_cast<SOCKET>(static_cast<std::uintptr_t>(fd_)),
                       FIONBIO, &nbio) == SOCKET_ERROR) {
        throw std::runtime_error(last_err_str("ioctlsocket FIONBIO"));
    }
#else
    const int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw std::runtime_error(std::string("F_SETFL O_NONBLOCK: ") + strerror(errno));
    }
#endif
}

void Socket::set_reuseaddr() {
    int one = 1;
#if defined(_WIN32)
    setsockopt(static_cast<SOCKET>(static_cast<std::uintptr_t>(fd_)),
                SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<const char*>(&one), sizeof(one));
#else
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
}

std::ptrdiff_t Socket::write_some(std::span<const std::uint8_t> data) {
    if (data.empty()) return 0;
#if defined(_WIN32)
    const int n = ::send(
        static_cast<SOCKET>(static_cast<std::uintptr_t>(fd_)),
        reinterpret_cast<const char*>(data.data()),
        static_cast<int>(data.size()), 0);
    if (n == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINTR) return 0;
        return -1;
    }
    return n;
#else
    const ssize_t n = ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }
    return n;
#endif
}

std::ptrdiff_t Socket::read_some(std::span<std::uint8_t> out) {
    if (out.empty()) return kReadRetry;
#if defined(_WIN32)
    const int n = ::recv(
        static_cast<SOCKET>(static_cast<std::uintptr_t>(fd_)),
        reinterpret_cast<char*>(out.data()),
        static_cast<int>(out.size()), 0);
    if (n == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINTR) return kReadRetry;
        return -1;
    }
    return n;
#else
    const ssize_t n = ::recv(fd_, out.data(), out.size(), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return kReadRetry;
        return -1;
    }
    return n;
#endif
}

Socket tcp_listen(const std::string& host, std::uint16_t port, int backlog) {
#if defined(_WIN32)
    ensure_winsock();
    SOCKET ws = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ws == INVALID_SOCKET) {
        throw std::runtime_error(last_err_str("socket"));
    }
    Socket s{static_cast<int>(ws)};
    s.set_reuseaddr();
    s.set_nonblocking();
#else
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error(last_err_str("socket"));
    Socket s{fd};
    s.set_reuseaddr();
#endif
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (host == "0.0.0.0" || host.empty()) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (host == "127.0.0.1" || host == "localhost") {
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
            throw std::runtime_error("invalid bind host: " + host);
        }
    }
#if defined(_WIN32)
    if (::bind(static_cast<SOCKET>(static_cast<std::uintptr_t>(s.fd())),
                reinterpret_cast<sockaddr*>(&sa),
                sizeof(sa)) == SOCKET_ERROR) {
        throw std::runtime_error(last_err_str("bind"));
    }
    if (::listen(static_cast<SOCKET>(static_cast<std::uintptr_t>(s.fd())),
                  backlog) == SOCKET_ERROR) {
        throw std::runtime_error(last_err_str("listen"));
    }
#else
    if (::bind(s.fd(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        throw std::runtime_error(last_err_str("bind"));
    }
    if (::listen(s.fd(), backlog) < 0) {
        throw std::runtime_error(last_err_str("listen"));
    }
#endif
    return s;
}

Socket tcp_connect(const std::string& host, std::uint16_t port) {
#if defined(_WIN32)
    ensure_winsock();
    SOCKET ws = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ws == INVALID_SOCKET) throw std::runtime_error(last_err_str("socket"));
    Socket s{static_cast<int>(ws)};
#else
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error(last_err_str("socket"));
    Socket s{fd};
#endif
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (host == "127.0.0.1" || host == "localhost") {
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
            throw std::runtime_error("dns resolve failed: " + host);
        }
        sa.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
#if defined(_WIN32)
    if (::connect(static_cast<SOCKET>(static_cast<std::uintptr_t>(s.fd())),
                   reinterpret_cast<sockaddr*>(&sa),
                   sizeof(sa)) == SOCKET_ERROR) {
        throw std::runtime_error(last_err_str("connect"));
    }
    s.set_nonblocking();
    int one = 1;
    setsockopt(static_cast<SOCKET>(static_cast<std::uintptr_t>(s.fd())),
                IPPROTO_TCP, TCP_NODELAY,
                reinterpret_cast<const char*>(&one), sizeof(one));
#else
    if (::connect(s.fd(), reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        throw std::runtime_error(last_err_str("connect"));
    }
    s.set_nonblocking();
    int one = 1;
    setsockopt(s.fd(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
    return s;
}

Socket tcp_accept(int listen_fd) {
    sockaddr_in sa{};
#if defined(_WIN32)
    int slen = sizeof(sa);
    SOCKET ws = ::accept(
        static_cast<SOCKET>(static_cast<std::uintptr_t>(listen_fd)),
        reinterpret_cast<sockaddr*>(&sa), &slen);
    if (ws == INVALID_SOCKET) {
        const int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return Socket{-1};
        throw std::runtime_error(last_err_str("accept"));
    }
    Socket s{static_cast<int>(ws)};
    s.set_nonblocking();
    int one = 1;
    setsockopt(ws, IPPROTO_TCP, TCP_NODELAY,
                reinterpret_cast<const char*>(&one), sizeof(one));
    return s;
#else
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
#endif
}

}  // namespace fb::net
