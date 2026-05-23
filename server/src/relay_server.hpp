// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Embeddable relay event loop. The same code path powers the standalone
// `fb_server` binary (thin main.cpp wrapper) AND the in-app relay the desktop
// client runs on a background thread — so a user can just launch the desktop
// and host the network alongside it, no separate server process required.

#include <atomic>
#include <cstdint>
#include <string>

namespace fb::server {

struct RelayConfig {
    std::string   bind_host    = "127.0.0.1";  // "0.0.0.0" to accept remote peers
    std::uint16_t port         = 8765;          // native TCP frame listener
    std::uint16_t ws_port      = 0;             // 0 = disabled
    std::uint16_t tls_port     = 0;             // 0 = disabled (wss WebSocket)
    std::uint16_t tls_raw_port = 0;             // 0 = disabled (TLS raw frames)
    std::string   tls_cert;                     // PEM cert chain (for tls_*_port)
    std::string   tls_key;                      // PEM private key
    std::string   offline_db;                   // SQLite path; empty = in-memory
    bool          quiet        = false;         // suppress stderr banners (embedded)
};

// Run the relay until `stop` becomes true (polled ~200 ms). Blocks the calling
// thread; returns 0 on clean shutdown. Safe to run on a background thread —
// set `stop = true` from any thread and join.
int run_relay(const RelayConfig& cfg, std::atomic<bool>& stop);

}  // namespace fb::server
