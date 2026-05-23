// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/lan_discovery.hpp"

#include <chrono>
#include <cstring>

namespace fb::p2p {

namespace {
constexpr char    kMagic[4] = {'F', 'B', 'L', 'N'};
constexpr std::uint8_t kVersion = 1;
constexpr std::size_t  kBeaconLen = 4 + 1 + 32 + 2 + 2;  // 41
}  // namespace

std::vector<std::uint8_t> encode_lan_beacon(std::span<const std::uint8_t, 32> pubkey,
                                            std::uint16_t gossip_port,
                                            std::uint16_t relay_port) {
    std::vector<std::uint8_t> out;
    out.reserve(kBeaconLen);
    out.insert(out.end(), kMagic, kMagic + 4);
    out.push_back(kVersion);
    out.insert(out.end(), pubkey.begin(), pubkey.end());
    out.push_back(static_cast<std::uint8_t>((gossip_port >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(gossip_port & 0xff));
    out.push_back(static_cast<std::uint8_t>((relay_port >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(relay_port & 0xff));
    return out;
}

std::optional<LanBeacon> parse_lan_beacon(std::span<const std::uint8_t> d) {
    if (d.size() < kBeaconLen) return std::nullopt;
    if (std::memcmp(d.data(), kMagic, 4) != 0) return std::nullopt;
    if (d[4] != kVersion) return std::nullopt;
    LanBeacon b;
    std::memcpy(b.pubkey.data(), d.data() + 5, 32);
    b.gossip_port = static_cast<std::uint16_t>((d[37] << 8) | d[38]);
    b.relay_port  = static_cast<std::uint16_t>((d[39] << 8) | d[40]);
    return b;
}

}  // namespace fb::p2p

// ---------------------------------------------------------------------------
// Socket loop — POSIX. On Windows it's a no-op for now (the rest of the app,
// incl. the embedded relay, still runs; LAN auto-discovery is just absent).
// ---------------------------------------------------------------------------
#if !defined(_WIN32)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fb::p2p {

LanDiscovery::LanDiscovery(std::array<std::uint8_t, 32> self_pubkey,
                           std::uint16_t gossip_port, std::uint16_t relay_port,
                           PeerCallback on_peer)
    : self_pubkey_(self_pubkey),
      gossip_port_(gossip_port),
      relay_port_(relay_port),
      on_peer_(std::move(on_peer)) {}

LanDiscovery::~LanDiscovery() { stop(); }

bool LanDiscovery::start() {
    if (running_.load()) return true;

    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;

    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    // Lets several instances on one host share the port (dev + the case of
    // two clients on the same machine).
    ::setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(kPort);
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(s);
        return false;
    }

    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = ::inet_addr(kGroup);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (::setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        ::close(s);
        return false;   // multicast unavailable on this host/network
    }
    // Loop back to other members on the same host, keep it link-local.
    unsigned char loop = 1, ttl = 1;
    ::setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
    ::setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    // 1s recv timeout so the loop can re-beacon + check the stop flag.
    timeval tv{};
    tv.tv_sec = 1;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sock_ = s;
    stop_.store(false);
    running_.store(true);
    thread_ = std::thread([this]() { run(); });
    return true;
}

void LanDiscovery::stop() {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
    if (sock_ >= 0) { ::close(sock_); sock_ = -1; }
    running_.store(false);
}

void LanDiscovery::run() {
    sockaddr_in group{};
    group.sin_family = AF_INET;
    group.sin_addr.s_addr = ::inet_addr(kGroup);
    group.sin_port = htons(kPort);

    const auto beacon = encode_lan_beacon(
        std::span<const std::uint8_t, 32>(self_pubkey_.data(), 32),
        gossip_port_, relay_port_);

    auto last_beacon = std::chrono::steady_clock::time_point{};   // send immediately
    while (!stop_.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now - last_beacon >= std::chrono::seconds(3)) {
            ::sendto(sock_, beacon.data(), beacon.size(), 0,
                     reinterpret_cast<sockaddr*>(&group), sizeof(group));
            last_beacon = now;
        }

        std::uint8_t buf[128];
        sockaddr_in src{};
        socklen_t slen = sizeof(src);
        const ssize_t n = ::recvfrom(sock_, buf, sizeof(buf), 0,
                                     reinterpret_cast<sockaddr*>(&src), &slen);
        if (n <= 0) continue;   // timeout / interrupted → re-loop (re-beacon)

        auto parsed = parse_lan_beacon(
            std::span<const std::uint8_t>(buf, static_cast<std::size_t>(n)));
        if (!parsed) continue;
        if (parsed->pubkey == self_pubkey_) continue;   // our own beacon

        LanPeer peer;
        peer.pubkey      = parsed->pubkey;
        peer.gossip_port = parsed->gossip_port;
        peer.relay_port  = parsed->relay_port;
        char ipbuf[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &src.sin_addr, ipbuf, sizeof(ipbuf));
        peer.ip = ipbuf;
        if (on_peer_) on_peer_(peer);
    }
}

}  // namespace fb::p2p

#else  // _WIN32 — no-op stub (LAN discovery not yet wired for winsock).

namespace fb::p2p {
LanDiscovery::LanDiscovery(std::array<std::uint8_t, 32> self_pubkey,
                           std::uint16_t gossip_port, std::uint16_t relay_port,
                           PeerCallback on_peer)
    : self_pubkey_(self_pubkey), gossip_port_(gossip_port),
      relay_port_(relay_port), on_peer_(std::move(on_peer)) {}
LanDiscovery::~LanDiscovery() {}
bool LanDiscovery::start() { return false; }
void LanDiscovery::stop() {}
void LanDiscovery::run() {}
}  // namespace fb::p2p

#endif
