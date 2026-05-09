// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/bootstrap.hpp"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fb::p2p {

namespace {

bool hex_to_bytes(std::string_view hex, std::vector<std::uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nyb = [](char c, int& v) -> bool {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = 10 + (c - 'a'); return true; }
        if (c >= 'A' && c <= 'F') { v = 10 + (c - 'A'); return true; }
        return false;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = 0, lo = 0;
        if (!nyb(hex[i], hi) || !nyb(hex[i + 1], lo)) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string trim(std::string_view in) {
    std::size_t b = 0, e = in.size();
    while (b < e && std::isspace(static_cast<unsigned char>(in[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1]))) --e;
    return std::string(in.substr(b, e - b));
}

}  // namespace

BootstrapParseResult parse_bootstrap_text(const std::string& contents) {
    BootstrapParseResult out;
    std::istringstream is(contents);
    std::string line;
    while (std::getline(is, line)) {
        // Strip trailing \r (Windows line endings).
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        // Two whitespace-separated fields: hex_pubkey + addr.
        std::istringstream ls(trimmed);
        std::string hex_pub, addr;
        ls >> hex_pub >> addr;
        if (hex_pub.empty() || addr.empty()) {
            ++out.malformed_lines;
            continue;
        }
        std::vector<std::uint8_t> pubkey;
        if (!hex_to_bytes(hex_pub, pubkey) || pubkey.size() != 32) {
            ++out.malformed_lines;
            continue;
        }
        // Reject addresses that are obviously not URL-shaped — we
        // accept anything containing "://" so the format stays
        // open to future schemes (wss, tcp, libp2p-quic, …) without
        // having to enumerate them.
        if (addr.find("://") == std::string::npos) {
            ++out.malformed_lines;
            continue;
        }
        PeerInfo p{};
        p.id = node_id_from_pubkey(std::span<const std::uint8_t>(
            pubkey.data(), pubkey.size()));
        p.addr = std::move(addr);
        p.pubkey = std::move(pubkey);
        out.peers.push_back(std::move(p));
    }
    return out;
}

BootstrapParseResult load_bootstrap_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        throw std::runtime_error(
            "load_bootstrap_file: could not open " + path);
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return parse_bootstrap_text(ss.str());
}

BootstrapParseResult load_default_bootstrap() {
    auto try_path = [](const std::string& p) -> BootstrapParseResult {
        if (p.empty()) return {};
        std::ifstream in(p);
        if (!in.is_open()) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        return parse_bootstrap_text(ss.str());
    };

    auto env = [](const char* k) -> std::string {
        const char* v = std::getenv(k);
        return v ? std::string(v) : std::string();
    };

    auto candidates = [&]() -> std::vector<std::string> {
        std::vector<std::string> v;
        if (auto x = env("FB_BOOTSTRAP_FILE"); !x.empty()) v.push_back(x);
        if (auto x = env("XDG_CONFIG_HOME"); !x.empty()) {
            v.push_back(x + "/finbit/bootstrap.txt");
        }
        if (auto x = env("HOME"); !x.empty()) {
            v.push_back(x + "/.finbit/bootstrap.txt");
        }
        v.emplace_back("/etc/finbit/bootstrap.txt");
        return v;
    }();

    for (const auto& c : candidates) {
        auto r = try_path(c);
        if (!r.peers.empty() || r.malformed_lines > 0) return r;
    }
    return {};
}

}  // namespace fb::p2p
