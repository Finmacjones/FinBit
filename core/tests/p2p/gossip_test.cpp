// SPDX-License-Identifier: AGPL-3.0-or-later
// Multi-node gossip pubsub test. Spins up 3 in-process P2PNodes on
// loopback, joins them in a chain (A <-> B <-> C), and verifies that a
// publish from A reaches the other two via gossip relay.

#include "fb/p2p/gossip.hpp"

#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace {

std::uint16_t free_port() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    socklen_t l = sizeof(sa);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &l);
    const std::uint16_t p = ntohs(sa.sin_port);
    ::close(fd);
    return p;
}

std::vector<std::uint8_t> rand_pubkey() {
    std::vector<std::uint8_t> out(32);
    std::random_device rd;
    std::uniform_int_distribution<std::uint16_t> d(0, 255);
    for (auto& b : out) b = static_cast<std::uint8_t>(d(rd));
    return out;
}

}  // namespace

TEST(P2PGossip, ThreeNodeChainDelivers) {
    const auto pa = free_port(), pb = free_port(), pc = free_port();
    fb::p2p::P2PNode A("127.0.0.1", pa, rand_pubkey());
    fb::p2p::P2PNode B("127.0.0.1", pb, rand_pubkey());
    fb::p2p::P2PNode C("127.0.0.1", pc, rand_pubkey());
    A.start(); B.start(); C.start();

    // A <-> B <-> C  (B is in the middle so messages from A must be relayed)
    A.dial("127.0.0.1", pb);
    C.dial("127.0.0.1", pb);

    // Give handshakes a moment.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::mutex mu;
    std::condition_variable cv;
    std::atomic_int recv_count{0};
    std::vector<std::vector<std::uint8_t>> got;
    auto on_msg = [&](const std::string& topic, std::span<const std::uint8_t> payload,
                      const fb::p2p::PeerInfo&) {
        EXPECT_EQ(topic, "topic-x");
        std::lock_guard lk(mu);
        got.emplace_back(payload.begin(), payload.end());
        ++recv_count;
        cv.notify_all();
    };
    A.set_on_topic_message(on_msg);
    B.set_on_topic_message(on_msg);
    C.set_on_topic_message(on_msg);

    A.subscribe("topic-x");
    B.subscribe("topic-x");
    C.subscribe("topic-x");

    // Let subscriptions propagate.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const std::vector<std::uint8_t> payload = {'h', 'i', '-', 'p', '2', 'p'};
    A.publish("topic-x",
              std::span<const std::uint8_t>(payload.data(), payload.size()),
              /*ttl=*/4);

    {
        std::unique_lock lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2), [&] { return recv_count >= 2; }))
            << "expected at least 2 receivers (B + C); got " << recv_count;
    }
    for (const auto& g : got) {
        EXPECT_EQ(g, payload);
    }

    A.stop(); B.stop(); C.stop();
}

TEST(P2PGossip, DuplicateDropped) {
    const auto pa = free_port(), pb = free_port();
    fb::p2p::P2PNode A("127.0.0.1", pa, rand_pubkey());
    fb::p2p::P2PNode B("127.0.0.1", pb, rand_pubkey());
    A.start(); B.start();
    A.dial("127.0.0.1", pb);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::atomic_int delivered{0};
    B.set_on_topic_message([&](const std::string&, std::span<const std::uint8_t>,
                               const fb::p2p::PeerInfo&) { ++delivered; });
    A.subscribe("dup");
    B.subscribe("dup");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const std::vector<std::uint8_t> payload = {1, 2, 3};
    A.publish("dup", std::span<const std::uint8_t>(payload.data(), payload.size()), 4);
    A.publish("dup", std::span<const std::uint8_t>(payload.data(), payload.size()), 4);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(delivered, 2);  // B sees both publishes (different message_ids)
    A.stop(); B.stop();
}

TEST(P2PGossip, CarryGuardCanRefuseRelay) {
    const auto pa = free_port(), pb = free_port(), pc = free_port();
    fb::p2p::P2PNode A("127.0.0.1", pa, rand_pubkey());
    fb::p2p::P2PNode B("127.0.0.1", pb, rand_pubkey());
    fb::p2p::P2PNode C("127.0.0.1", pc, rand_pubkey());
    A.start(); B.start(); C.start();

    A.dial("127.0.0.1", pb);
    C.dial("127.0.0.1", pb);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // B refuses to carry anything.
    B.set_carry_guard([](const fb::p2p::PeerInfo&, std::uint64_t) { return false; });

    std::atomic_int c_delivered{0};
    C.set_on_topic_message([&](const std::string&, std::span<const std::uint8_t>,
                               const fb::p2p::PeerInfo&) { ++c_delivered; });
    A.subscribe("guarded");
    B.subscribe("guarded");
    C.subscribe("guarded");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const std::vector<std::uint8_t> payload = {7};
    A.publish("guarded", std::span<const std::uint8_t>(payload.data(), payload.size()), 4);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // C never receives because B refused to relay.
    EXPECT_EQ(c_delivered, 0) << "carry guard should have blocked the relay";

    A.stop(); B.stop(); C.stop();
}
