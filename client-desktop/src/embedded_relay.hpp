// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// EmbeddedRelay — runs the FinBit relay (fb::server::run_relay) on a background
// thread inside the desktop process, so launching the client also hosts a
// network node. Lifecycle-safe: start() reaps any prior worker before spawning
// (never reassigns over a joinable thread → no std::terminate), stop()/dtor
// signal the loop and join.

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

#include "relay_server.hpp"

namespace fb::desktop {

class EmbeddedRelay {
public:
    EmbeddedRelay() = default;
    ~EmbeddedRelay() { stop(); }

    EmbeddedRelay(const EmbeddedRelay&) = delete;
    EmbeddedRelay& operator=(const EmbeddedRelay&) = delete;

    // Start the relay with `cfg` on a background thread. No-op if already
    // running. Reaps a previously-finished worker first (defensive).
    void start(const fb::server::RelayConfig& cfg) {
        if (running_.load()) return;
        if (thread_.joinable()) thread_.join();   // reap a prior finished worker
        cfg_ = cfg;
        cfg_.quiet = true;                          // no stderr banners in-app
        stop_flag_.store(false);
        start_error_.store(false);
        running_.store(true);
        thread_ = std::thread([this]() {
            // Catch everything: a bind failure (port already in use) must not
            // std::terminate the whole desktop process — the relay just won't
            // run, and the client can still connect elsewhere.
            try {
                fb::server::run_relay(cfg_, stop_flag_);
            } catch (...) {
                start_error_.store(true);
            }
            running_.store(false);
        });
    }

    // Signal the loop to exit and join. Idempotent.
    void stop() {
        stop_flag_.store(true);
        if (thread_.joinable()) thread_.join();
        running_.store(false);
    }

    [[nodiscard]] bool          running() const { return running_.load(); }
    [[nodiscard]] bool          had_error() const { return start_error_.load(); }
    [[nodiscard]] std::string   host() const { return cfg_.bind_host; }
    [[nodiscard]] std::uint16_t port() const { return cfg_.port; }

private:
    fb::server::RelayConfig cfg_;
    std::atomic<bool>       stop_flag_{false};
    std::atomic<bool>       running_{false};
    std::atomic<bool>       start_error_{false};
    std::thread             thread_;
};

}  // namespace fb::desktop
