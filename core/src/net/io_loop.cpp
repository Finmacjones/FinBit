// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/io_loop.hpp"

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <queue>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fb::net {

struct IoLoop::Impl {
    int epfd = -1;
    int timerfd = -1;
    int wake_r = -1;
    int wake_w = -1;
    std::atomic_bool running{false};
    std::unordered_map<int, FdReadyCallback> handlers;

    struct PendingTimer {
        std::chrono::steady_clock::time_point at;
        TimerCallback cb;
        bool operator>(const PendingTimer& o) const noexcept { return at > o.at; }
    };
    std::priority_queue<PendingTimer, std::vector<PendingTimer>, std::greater<PendingTimer>>
        timers;

    void rearm_timer() {
        itimerspec spec{};
        if (!timers.empty()) {
            const auto now = std::chrono::steady_clock::now();
            auto next = timers.top().at;
            if (next < now) next = now;
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(next - now).count();
            spec.it_value.tv_sec = ns / 1'000'000'000;
            spec.it_value.tv_nsec = ns % 1'000'000'000;
            if (spec.it_value.tv_sec == 0 && spec.it_value.tv_nsec == 0) {
                spec.it_value.tv_nsec = 1;  // 0/0 disarms; we want to fire immediately
            }
        }
        timerfd_settime(timerfd, 0, &spec, nullptr);
    }
};

IoLoop::IoLoop() : impl_(std::make_unique<Impl>()) {
    impl_->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (impl_->epfd < 0) throw std::runtime_error(std::string("epoll_create1: ") + strerror(errno));
    impl_->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (impl_->timerfd < 0)
        throw std::runtime_error(std::string("timerfd_create: ") + strerror(errno));
    epoll_event ev{};
    ev.events = EPOLLIN;
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
    wev.events = EPOLLIN;
    wev.data.fd = impl_->wake_r;
    if (epoll_ctl(impl_->epfd, EPOLL_CTL_ADD, impl_->wake_r, &wev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl(wake): ") + strerror(errno));
    }
}

IoLoop::~IoLoop() {
    if (impl_) {
        if (impl_->wake_r >= 0) ::close(impl_->wake_r);
        if (impl_->wake_w >= 0) ::close(impl_->wake_w);
        if (impl_->timerfd >= 0) ::close(impl_->timerfd);
        if (impl_->epfd >= 0) ::close(impl_->epfd);
    }
}

void IoLoop::add_fd(int fd, std::uint32_t events, FdReadyCallback cb) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    auto it = impl_->handlers.find(fd);
    const int op = (it == impl_->handlers.end()) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(impl_->epfd, op, fd, &ev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl: ") + strerror(errno));
    }
    impl_->handlers[fd] = std::move(cb);
}

void IoLoop::mod_fd(int fd, std::uint32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(impl_->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        throw std::runtime_error(std::string("epoll_ctl(mod): ") + strerror(errno));
    }
}

void IoLoop::remove_fd(int fd) {
    epoll_ctl(impl_->epfd, EPOLL_CTL_DEL, fd, nullptr);
    impl_->handlers.erase(fd);
}

void IoLoop::schedule(std::chrono::milliseconds delay, TimerCallback cb) {
    impl_->timers.push({std::chrono::steady_clock::now() + delay, std::move(cb)});
    impl_->rearm_timer();
}

void IoLoop::run() {
    impl_->running = true;
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
                // Drain wake byte(s); the running flag was already toggled.
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
                while (!impl_->timers.empty() && impl_->timers.top().at <= now) {
                    auto cb = std::move(impl_->timers.top().cb);
                    impl_->timers.pop();
                    cb();
                }
                impl_->rearm_timer();
                continue;
            }
            auto it = impl_->handlers.find(fd);
            if (it != impl_->handlers.end()) {
                it->second(fd, ev);
            }
        }
    }
}

void IoLoop::stop() {
    impl_->running = false;
    // Wake the loop if it's currently blocked in epoll_wait.
    if (impl_->wake_w >= 0) {
        const std::uint8_t b = 0;
        ssize_t r;
        do {
            r = ::write(impl_->wake_w, &b, 1);
        } while (r < 0 && errno == EINTR);
    }
}

}  // namespace fb::net
