// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// LAN discovery beacon — zero-config peer finding on a local network.
//
// The P2P overlay (gossip / DHT) solves "talk to a peer once you know one",
// but not "find the first peer" without a bootstrap list. On a shared network
// (home / office / event Wi-Fi) we can close that gap with a UDP multicast
// beacon: every node periodically announces { pubkey, gossip_port, relay_port }
// to a fixed group, and on hearing another node's beacon it learns where to
// dial. So users just launch the desktop and the nodes federate themselves —
// no addresses to type, no bootstrap file.
//
// Scope: link-local only (multicast TTL = 1). The internet still needs a
// bootstrap list (fb::p2p::load_default_bootstrap). Pure encode/parse helpers
// are split out so the wire format is unit-testable without sockets.
// =============================================================================

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace fb::p2p {

// Decoded beacon contents (the source IP is taken from the UDP datagram, not
// the payload, so a node can't lie about its own address).
struct LanBeacon {
    std::array<std::uint8_t, 32> pubkey{};
    std::uint16_t                gossip_port = 0;
    std::uint16_t                relay_port  = 0;
};

// A discovered peer = a parsed beacon + the address it came from.
struct LanPeer {
    std::array<std::uint8_t, 32> pubkey{};
    std::string                  ip;            // dotted-quad from recvfrom
    std::uint16_t                gossip_port = 0;
    std::uint16_t                relay_port  = 0;
};

// Wire format (41 bytes): "FBLN" | ver(1) | pubkey(32) | gossip_port(BE u16)
// | relay_port(BE u16). Versioned so the format can grow.
[[nodiscard]] std::vector<std::uint8_t> encode_lan_beacon(
    std::span<const std::uint8_t, 32> pubkey,
    std::uint16_t gossip_port, std::uint16_t relay_port);

[[nodiscard]] std::optional<LanBeacon> parse_lan_beacon(
    std::span<const std::uint8_t> datagram);

class LanDiscovery {
public:
    using PeerCallback = std::function<void(const LanPeer&)>;

    // `self_pubkey` filters our own beacons out. The callback fires (on the
    // discovery thread) for every OTHER node heard. gossip_port/relay_port are
    // what we advertise for ourselves; pass 0 to advertise "none".
    LanDiscovery(std::array<std::uint8_t, 32> self_pubkey,
                 std::uint16_t gossip_port, std::uint16_t relay_port,
                 PeerCallback on_peer);
    ~LanDiscovery();

    LanDiscovery(const LanDiscovery&) = delete;
    LanDiscovery& operator=(const LanDiscovery&) = delete;

    // Join the multicast group and start the beacon + listen thread. Returns
    // false if the socket couldn't be set up (multicast unavailable); the rest
    // of the app keeps working, just without LAN auto-discovery.
    bool start();
    void stop();

    [[nodiscard]] bool running() const { return running_.load(); }

    static constexpr std::uint16_t  kPort  = 47474;
    static constexpr const char*    kGroup = "239.255.77.77";  // admin-scoped

private:
    void run();   // beacon + recv loop

    std::array<std::uint8_t, 32> self_pubkey_{};
    std::uint16_t                gossip_port_;
    std::uint16_t                relay_port_;
    PeerCallback                 on_peer_;
    int                          sock_ = -1;
    std::atomic<bool>            stop_{false};
    std::atomic<bool>            running_{false};
    std::thread                  thread_;
};

}  // namespace fb::p2p
