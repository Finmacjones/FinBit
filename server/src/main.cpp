// SPDX-License-Identifier: AGPL-3.0-or-later
// fb_server — thin CLI wrapper around the embeddable relay event loop
// (fb::server::run_relay, server/src/relay_server.cpp). All the networking +
// routing lives in the library so the desktop client can host the same relay
// in-process; this file is just arg-parsing + signal handling.

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#if defined(_WIN32)
#  include <windows.h>
#endif

#include "fb/config/build_config.hpp"
#include "relay_server.hpp"

namespace {
std::atomic_bool g_stop{false};
#if defined(_WIN32)
BOOL WINAPI on_ctrl_event(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}
#else
void on_signal(int) { g_stop = true; }
#endif
}  // namespace

int main(int argc, char** argv) {
    // Unbuffered so logs land in real time under a supervisor / CI runner.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    fb::server::RelayConfig cfg;
    bool public_listen = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) cfg.port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--host" && i + 1 < argc) cfg.bind_host = argv[++i];
        else if (a == "--ws-port" && i + 1 < argc)
            cfg.ws_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--tls-port" && i + 1 < argc)
            cfg.tls_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--tls-raw-port" && i + 1 < argc)
            cfg.tls_raw_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--tls-cert" && i + 1 < argc) cfg.tls_cert = argv[++i];
        else if (a == "--tls-key"  && i + 1 < argc) cfg.tls_key  = argv[++i];
        else if (a == "--offline-db" && i + 1 < argc) cfg.offline_db = argv[++i];
        else if (a == "--amnesia") cfg.amnesia = true;
        else if (a == "--public") public_listen = true;
        else if (a == "--help" || a == "-h") {
            std::fprintf(stderr,
                "usage: fb_server [--host H] [--port P] [--ws-port P]\n"
                "                 [--public] [--offline-db PATH]\n"
                "                 [--tls-port P] [--tls-raw-port P]\n"
                "                 [--tls-cert F] [--tls-key F]\n\n"
                "  --host H        bind address (default 127.0.0.1 — localhost only)\n"
                "  --public        shortcut for --host 0.0.0.0 (every interface)\n"
                "  --port P        native TCP frame listener (default 8765)\n"
                "  --ws-port P     WebSocket listener for browser/Node clients (off)\n"
                "  --tls-port P    TLS-wrapped WebSocket (wss://); needs --tls-cert/key\n"
                "  --tls-raw-port P TLS-wrapped raw frames (native TLS); needs cert/key\n"
                "  --tls-cert F    PEM certificate chain\n"
                "  --tls-key F     PEM private key\n"
                "  --offline-db F  SQLite path for offline queue + directory (else RAM)\n"
                "  --amnesia       NEVER persist to disk — even when --offline-db is set,\n"
                "                  the path is force-cleared. RAM-only operation; power\n"
                "                  off = total state loss. Use to advertise that no\n"
                "                  subpoena can compel data the operator doesn't have.\n"
                "                  Pair with docs/warrant-canary.md.\n\n"
                "Self-signed cert for local testing:\n"
                "  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \\\n"
                "    -keyout key.pem -out cert.pem -subj /CN=localhost\n\n"
                "The same relay can run inside the desktop client (Settings ▸ host a\n"
                "relay) so users need no separate server.\n"
                "placeholder URL constant: %s\n",
                std::string(fb::config::kDefaultServerUrl).c_str());
            return 0;
        }
    }
    if (public_listen) cfg.bind_host = "0.0.0.0";

#if defined(_WIN32)
    SetConsoleCtrlHandler(on_ctrl_event, TRUE);
#else
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
#endif

    const int rc = fb::server::run_relay(cfg, g_stop);
    std::fprintf(stderr, "[server] shutting down\n");
    return rc;
}
