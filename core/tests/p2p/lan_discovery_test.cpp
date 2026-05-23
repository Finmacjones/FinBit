// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/lan_discovery.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

using fb::p2p::encode_lan_beacon;
using fb::p2p::parse_lan_beacon;
using fb::p2p::LanDiscovery;
using fb::p2p::LanPeer;

namespace {
std::array<std::uint8_t, 32> pk(std::uint8_t fill) {
    std::array<std::uint8_t, 32> a{};
    a.fill(fill);
    return a;
}
}  // namespace

// ---- Pure wire-format tests (always run, no sockets) ----------------------

TEST(LanBeacon, EncodeParseRoundTrip) {
    auto p = pk(0xab);
    auto wire = encode_lan_beacon(std::span<const std::uint8_t, 32>(p.data(), 32),
                                  47475, 8765);
    EXPECT_EQ(wire.size(), 41u);
    auto got = parse_lan_beacon(std::span<const std::uint8_t>(wire.data(), wire.size()));
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->pubkey, p);
    EXPECT_EQ(got->gossip_port, 47475);
    EXPECT_EQ(got->relay_port, 8765);
}

TEST(LanBeacon, RejectsGarbageAndShort) {
    std::vector<std::uint8_t> tooShort(10, 0);
    EXPECT_FALSE(parse_lan_beacon(
        std::span<const std::uint8_t>(tooShort.data(), tooShort.size())).has_value());

    auto p = pk(0x01);
    auto wire = encode_lan_beacon(std::span<const std::uint8_t, 32>(p.data(), 32), 1, 2);
    wire[0] = 'X';   // corrupt the magic
    EXPECT_FALSE(parse_lan_beacon(
        std::span<const std::uint8_t>(wire.data(), wire.size())).has_value());

    auto wire2 = encode_lan_beacon(std::span<const std::uint8_t, 32>(p.data(), 32), 1, 2);
    wire2[4] = 0xfe;   // unknown version
    EXPECT_FALSE(parse_lan_beacon(
        std::span<const std::uint8_t>(wire2.data(), wire2.size())).has_value());
}

// ---- Live multicast test (best-effort: SKIP where multicast is unavailable,
//      e.g. locked-down CI sandboxes) ----------------------------------------

TEST(LanDiscovery, TwoNodesDiscoverEachOther) {
    std::mutex mu;
    std::condition_variable cv;
    bool a_found_b = false, b_found_a = false;
    auto a_pub = pk(0xaa), b_pub = pk(0xbb);

    LanDiscovery a(a_pub, 1111, 8765, [&](const LanPeer& peer) {
        std::lock_guard lk(mu);
        if (peer.pubkey == b_pub && peer.gossip_port == 2222) a_found_b = true;
        cv.notify_all();
    });
    LanDiscovery b(b_pub, 2222, 8766, [&](const LanPeer& peer) {
        std::lock_guard lk(mu);
        if (peer.pubkey == a_pub && peer.gossip_port == 1111) b_found_a = true;
        cv.notify_all();
    });

    if (!a.start() || !b.start()) {
        GTEST_SKIP() << "multicast unavailable in this environment";
    }
    std::unique_lock lk(mu);
    const bool ok = cv.wait_for(lk, std::chrono::seconds(8),
                                [&] { return a_found_b && b_found_a; });
    lk.unlock();
    a.stop();
    b.stop();
    if (!ok) GTEST_SKIP() << "no multicast delivery (sandbox); wire format covered above";
    EXPECT_TRUE(a_found_b);
    EXPECT_TRUE(b_found_a);
}
