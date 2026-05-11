// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/io_loop.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
// Winsock2 must be included BEFORE windows.h (which is dragged in
// transitively). We don't include windows.h directly anywhere here.
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <array>
#  include <fcntl.h>
#  include <sys/epoll.h>
#  include <sys/timerfd.h>
#  include <unistd.h>
#endif

namespace fb::net {

#if defined(_WIN32)
// One-shot Winsock initialiser. Constructed at first IoLoop creation,
// destroyed at program exit. WSAStartup is reference-counted internally;
// we only ever take one ref.
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
static WinsockInit& ensure_winsock() {
    static WinsockInit one;
    return one;
}

namespace {
// Create a loopback TCP socket pair to serve as the cross-thread
// wake mechanism (pipe2() doesn't exist on Windows). One side
// listens on 127.0.0.1:0, the other connects, then we accept and
// close the listener. Both ends are made non-blocking.
std::pair<SOCKET, SOCKET> make_wake_pair() {
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        throw std::runtime_error("wake socket(listen): " +
                                  std::to_string(WSAGetLastError()));
    }
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))
            == SOCKET_ERROR) {
        ::closesocket(listener);
        throw std::runtime_error("wake bind: " +
                                  std::to_string(WSAGetLastError()));
    }
    if (::listen(listener, 1) == SOCKET_ERROR) {
        ::closesocket(listener);
        throw std::runtime_error("wake listen: " +
                                  std::to_string(WSAGetLastError()));
    }
    int addrlen = sizeof(addr);
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&addr),
                       &addrlen) == SOCKET_ERROR) {
        ::closesocket(listener);
        throw std::runtime_error("wake getsockname: " +
                                  std::to_string(WSAGetLastError()));
    }
    SOCKET client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        ::closesocket(listener);
        throw std::runtime_error("wake socket(client): " +
                                  std::to_string(WSAGetLastError()));
    }
    if (::connect(client, reinterpret_cast<sockaddr*>(&addr),
                   sizeof(addr)) == SOCKET_ERROR) {
        ::closesocket(client);
        ::closesocket(listener);
        throw std::runtime_error("wake connect: " +
                                  std::to_string(WSAGetLastError()));
    }
    SOCKET server = ::accept(listener, nullptr, nullptr);
    ::closesocket(listener);
    if (server == INVALID_SOCKET) {
        ::closesocket(client);
        throw std::runtime_error("wake accept: " +
                                  std::to_string(WSAGetLastError()));
    }
    u_long nbio = 1;
    ::ioctlsocket(server, FIONBIO, &nbio);
    ::ioctlsocket(client, FIONBIO, &nbio);
    return {server, client};   // (read end, write end)
}
}  // namespace
#endif  // _WIN32

struct IoLoop::Impl {
#if defined(_WIN32)
    SOCKET wake_r = INVALID_SOCKET;
    SOCKET wake_w = INVALID_SOCKET;
    // On Windows, WSAPoll has no central registration; we keep the
    // wanted events per-fd alongside the callback and rebuild the
    // pollset every iteration.
    std::unordered_map<int, std::uint32_t> events_for_fd;
#else
    int epfd    = -1;
    int timerfd = -1;
    int wake_r  = -1;
    int wake_w  = -1;
#endif
    std::atomic_bool running{false};
    // `mu` protects `handlers`, `events_for_fd` (Windows only), and
    // `timers` against concurrent access from arbitrary registrant
    // threads and the I/O thread. Caught by TSan in the security
    // validation pass.
    std::mutex mu;
    std::unordered_map<int, FdReadyCallback> handlers;

    struct PendingTimer {
        std::chrono::steady_clock::time_point at;
        TimerCallback cb;
        bool operator>(const PendingTimer& o) const noexcept { return at > o.at; }
    };
    std::priority_queue<PendingTimer, std::vector<PendingTimer>,
                        std::greater<PendingTimer>> timers;

#if !defined(_WIN32)
    void rearm_timer() {
        itimerspec spec{};
        if (!timers.empty()) {
            const auto now = std::chrono::steady_clock::now();
            auto next = timers.top().at;
            if (next < now) next = now;
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                next - now).count();
            spec.it_value.tv_sec  = ns / 1'000'000'000;
            spec.it_value.tv_nsec = ns % 1'000'000'000;
            if (spec.it_value.tv_sec == 0 && spec.it_value.tv_nsec == 0) {
                spec.it_value.tv_nsec = 1;
            }
        }
        timerfd_settime(timerfd, 0, &spec, nullptr);
    }
#endif
};

IoLoop::IoLoop() : impl_(std::make_unique<Impl>()) {
#if defined(_WIN32)
    ensure_winsock();
    auto [r, w]    = make_wake_pair();
    impl_->wake_r  = r;
    impl_->wake_w  = w;
#else
    impl_->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (impl_->epfd < 0)
        throw std::runtime_error(std::string("epoll_create1: ") + strerror(errno));
    impl_->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (impl_->timerfd < 0)
        throw std::runtime_error(std::string("timerfd_create: ") + strerror(errno));
    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = impl_->timerfd;
    if (epoll_ctl(impl_->epfd, EPOLL_CTL_ADD, impl_->timerfd, &ev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl(timerfd): ") + strerror(errno));
    }
    int pipefds[2];
    if (pipe2(pipefds, O_CLOEXEC | O_NONBLOCK) < 0) {
        throw std::runtime_error(std::string("pipe2: ") + strerror(errno));
    }
    impl_->wake_r = pipefds[0];
    impl_->wake_w = pipefds[1];
    epoll_event wev{};
    wev.events  = EPOLLIN;
    wev.data.fd = impl_->wake_r;
    if (epoll_ctl(impl_->epfd, EPOLL_CTL_ADD, impl_->wake_r, &wev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl(wake): ") + strerror(errno));
    }
#endif
}

IoLoop::~IoLoop() {
    if (!impl_) return;
#if defined(_WIN32)
    if (impl_->wake_r != INVALID_SOCKET) ::closesocket(impl_->wake_r);
    if (impl_->wake_w != INVALID_SOCKET) ::closesocket(impl_->wake_w);
#else
    if (impl_->wake_r  >= 0) ::close(impl_->wake_r);
    if (impl_->wake_w  >= 0) ::close(impl_->wake_w);
    if (impl_->timerfd >= 0) ::close(impl_->timerfd);
    if (impl_->epfd    >= 0) ::close(impl_->epfd);
#endif
}

void IoLoop::add_fd(int fd, std::uint32_t events, FdReadyCallback cb) {
#if defined(_WIN32)
    {
        std::lock_guard lk(impl_->mu);
        impl_->events_for_fd[fd] = events;
        impl_->handlers[fd]      = std::move(cb);
    }
    // Wake the loop so the next poll iteration sees the new fd.
    const char b = 0;
    ::send(impl_->wake_w, &b, 1, 0);
#else
    epoll_event ev{};
    ev.events  = events;
    ev.data.fd = fd;
    bool exists;
    {
        std::lock_guard lk(impl_->mu);
        exists = impl_->handlers.find(fd) != impl_->handlers.end();
    }
    const int op = exists ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(impl_->epfd, op, fd, &ev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl: ") + strerror(errno));
    }
    std::lock_guard lk(impl_->mu);
    impl_->handlers[fd] = std::move(cb);
#endif
}

void IoLoop::mod_fd(int fd, std::uint32_t events) {
#if defined(_WIN32)
    std::lock_guard lk(impl_->mu);
    impl_->events_for_fd[fd] = events;
    // No explicit wake needed for mod; existing pollset rebuilds
    // every iteration anyway.
#else
    epoll_event ev{};
    ev.events  = events;
    ev.data.fd = fd;
    if (epoll_ctl(impl_->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl(mod): ") + strerror(errno));
    }
#endif
}

void IoLoop::remove_fd(int fd) {
#if defined(_WIN32)
    std::lock_guard lk(impl_->mu);
    impl_->events_for_fd.erase(fd);
    impl_->handlers.erase(fd);
#else
    epoll_ctl(impl_->epfd, EPOLL_CTL_DEL, fd, nullptr);
    std::lock_guard lk(impl_->mu);
    impl_->handlers.erase(fd);
#endif
}

void IoLoop::schedule(std::chrono::milliseconds delay, TimerCallback cb) {
#if defined(_WIN32)
    {
        std::lock_guard lk(impl_->mu);
        impl_->timers.push({std::chrono::steady_clock::now() + delay,
                            std::move(cb)});
    }
    // Wake the loop so it recomputes its poll timeout.
    const char b = 0;
    ::send(impl_->wake_w, &b, 1, 0);
#else
    {
        std::lock_guard lk(impl_->mu);
        impl_->timers.push({std::chrono::steady_clock::now() + delay,
                            std::move(cb)});
    }
    impl_->rearm_timer();
#endif
}

void IoLoop::run() {
    impl_->running = true;
#if defined(_WIN32)
    std::vector<WSAPOLLFD> pollset;
    while (impl_->running) {
        pollset.clear();
        // Always include the wake socket at index 0.
        WSAPOLLFD wakefd{};
        wakefd.fd      = impl_->wake_r;
        wakefd.events  = POLLRDNORM;
        wakefd.revents = 0;
        pollset.push_back(wakefd);

        // Snapshot user fds + compute next-timer timeout under lock.
        int timeout_ms = -1;
        {
            std::lock_guard lk(impl_->mu);
            for (auto& [fd, ev] : impl_->events_for_fd) {
                WSAPOLLFD pfd{};
                pfd.fd = static_cast<SOCKET>(static_cast<std::uintptr_t>(fd));
                pfd.events = 0;
                if (ev & EPOLLIN)  pfd.events |= POLLRDNORM;
                if (ev & EPOLLOUT) pfd.events |= POLLWRNORM;
                pfd.revents = 0;
                pollset.push_back(pfd);
            }
            if (!impl_->timers.empty()) {
                auto now = std::chrono::steady_clock::now();
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    impl_->timers.top().at - now).count();
                if (ms < 0) ms = 0;
                if (ms > std::numeric_limits<int>::max())
                    ms = std::numeric_limits<int>::max();
                timeout_ms = static_cast<int>(ms);
            }
        }

        int n = WSAPoll(pollset.data(),
                         static_cast<ULONG>(pollset.size()),
                         timeout_ms);
        if (n == SOCKET_ERROR) {
            const int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            throw std::runtime_error("WSAPoll: " + std::to_string(err));
        }

        // Drain expired timers regardless of WSAPoll wake reason.
        {
            const auto now = std::chrono::steady_clock::now();
            std::vector<TimerCallback> ready;
            {
                std::lock_guard lk(impl_->mu);
                while (!impl_->timers.empty() &&
                       impl_->timers.top().at <= now) {
                    ready.push_back(std::move(
                        const_cast<Impl::PendingTimer&>(
                            impl_->timers.top()).cb));
                    impl_->timers.pop();
                }
            }
            for (auto& cb : ready) cb();
        }

        if (n <= 0) continue;
        for (size_t i = 0; i < pollset.size(); ++i) {
            if (pollset[i].revents == 0) continue;
            if (pollset[i].fd == impl_->wake_r) {
                char drain[64];
                while (::recv(impl_->wake_r, drain, sizeof(drain), 0) > 0) {}
                continue;
            }
            std::uint32_t ev = 0;
            if (pollset[i].revents & POLLRDNORM) ev |= EPOLLIN;
            if (pollset[i].revents & POLLWRNORM) ev |= EPOLLOUT;
            if (pollset[i].revents & POLLERR)    ev |= EPOLLERR;
            if (pollset[i].revents & POLLHUP)    ev |= EPOLLHUP;
            FdReadyCallback cb;
            const int fd_i = static_cast<int>(pollset[i].fd);
            {
                std::lock_guard lk(impl_->mu);
                auto it = impl_->handlers.find(fd_i);
                if (it != impl_->handlers.end()) cb = it->second;
            }
            if (cb) cb(fd_i, ev);
        }
    }
#else
    constexpr int kMaxEvents = 64;
    epoll_event events[kMaxEvents];
    while (impl_->running) {
        const int n = epoll_wait(impl_->epfd, events, kMaxEvents, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("epoll_wait: ") + strerror(errno));
        }
        for (int i = 0; i < n; ++i) {
            const int fd = events[i].data.fd;
            const std::uint32_t ev = events[i].events;
            if (fd == impl_->wake_r) {
                std::array<std::uint8_t, 64> drain;
                while (::read(impl_->wake_r, drain.data(), drain.size()) > 0) {}
                continue;
            }
            if (fd == impl_->timerfd) {
                std::uint64_t expirations = 0;
                ssize_t r;
                do {
                    r = ::read(impl_->timerfd, &expirations, sizeof(expirations));
                } while (r < 0 && errno == EINTR);
                const auto now = std::chrono::steady_clock::now();
                std::vector<TimerCallback> ready;
                {
                    std::lock_guard lk(impl_->mu);
                    while (!impl_->timers.empty() &&
                           impl_->timers.top().at <= now) {
                        ready.push_back(std::move(
                            const_cast<Impl::PendingTimer&>(
                                impl_->timers.top()).cb));
                        impl_->timers.pop();
                    }
                }
                for (auto& cb : ready) cb();
                impl_->rearm_timer();
                continue;
            }
            FdReadyCallback cb;
            {
                std::lock_guard lk(impl_->mu);
                auto it = impl_->handlers.find(fd);
                if (it != impl_->handlers.end()) cb = it->second;
            }
            if (cb) cb(fd, ev);
        }
    }
#endif
}

void IoLoop::stop() {
    impl_->running = false;
#if defined(_WIN32)
    if (impl_->wake_w != INVALID_SOCKET) {
        const char b = 0;
        ::send(impl_->wake_w, &b, 1, 0);
    }
#else
    if (impl_->wake_w >= 0) {
        const std::uint8_t b = 0;
        ssize_t r;
        do {
            r = ::write(impl_->wake_w, &b, 1);
        } while (r < 0 && errno == EINTR);
    }
#endif
}

}  // namespace fb::net
