// SPDX-License-Identifier: AGPL-3.0-or-later
// MQTT bridge round-trip test against an in-process Python broker (amqtt).
// The test spawns tools/mesh-loopback/mqtt_broker.py, connects two
// PahoBridges, sends a frame from one, asserts the other receives it.
//
// Skipped if either python3 or the amqtt module is unavailable; the build
// itself depends only on Paho, not on the broker.

#include "fb/mesh/bridge.hpp"

#include <gtest/gtest.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if !FB_HAVE_PAHO
TEST(MqttBridge, BuiltWithoutPaho_SkipReal) { GTEST_SKIP() << "FB_HAVE_PAHO=0"; }
#else

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

bool wait_listening(std::uint16_t port, int timeout_ms = 4000) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(port);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0) {
            ::close(fd);
            return true;
        }
        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

class BrokerProc {
public:
    explicit BrokerProc(std::uint16_t port) : port_(port) {
        const auto bind = std::string("127.0.0.1:") + std::to_string(port);
        const auto cmd = std::string(
                             "python3 /home/finmac/Documents/Discordclone/tools/"
                             "mesh-loopback/mqtt_broker.py ") +
                         bind + " >/tmp/fb_mqtt_broker.log 2>&1 &echo $!";
        FILE* f = ::popen(cmd.c_str(), "r");
        if (!f) return;
        char buf[32]{};
        if (fgets(buf, sizeof(buf), f)) pid_ = std::atoi(buf);
        ::pclose(f);
    }
    ~BrokerProc() {
        if (pid_ > 0) {
            ::kill(pid_, SIGTERM);
            // Best-effort wait
            for (int i = 0; i < 20; ++i) {
                if (::kill(pid_, 0) != 0) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
    [[nodiscard]] bool running() const { return pid_ > 0; }
    std::uint16_t port() const { return port_; }

private:
    std::uint16_t port_;
    int pid_ = -1;
};

bool python_amqtt_available() {
    int rc = std::system("python3 -c 'import amqtt' >/dev/null 2>&1");
    return rc == 0;
}

}  // namespace

TEST(MqttBridge, RoundTripViaEmbeddedBroker) {
    if (!python_amqtt_available()) {
        GTEST_SKIP() << "python3 amqtt unavailable on this box";
    }
    const auto port = free_port();
    BrokerProc broker(port);
    ASSERT_TRUE(broker.running()) << "failed to spawn the embedded broker";
    ASSERT_TRUE(wait_listening(port)) << "broker never started listening";

    const std::string url = "tcp://127.0.0.1:" + std::to_string(port);
    auto sub = fb::mesh::make_mqtt_bridge(url, "fbtest");
    auto pub = fb::mesh::make_mqtt_bridge(url, "fbtest");
    ASSERT_NE(sub, nullptr);
    ASSERT_NE(pub, nullptr);

    std::mutex mu;
    std::condition_variable cv;
    std::vector<std::uint8_t> got;
    sub->set_on_frame([&](const fb::mesh::MeshFrame& f) {
        std::lock_guard lk(mu);
        got = f.payload;
        cv.notify_all();
    });

    ASSERT_TRUE(sub->start()) << "subscriber failed to connect";
    ASSERT_TRUE(pub->start()) << "publisher failed to connect";
    // Tiny pause so the subscribe ACK propagates before we publish.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const std::vector<std::uint8_t> payload = {'h', 'i', '-', 'm', 'q', 't', 't'};
    ASSERT_TRUE(pub->send("primary",
                          std::span<const std::uint8_t>(payload.data(), payload.size())));

    {
        std::unique_lock lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(3), [&] { return !got.empty(); }))
            << "subscriber never saw the published frame";
    }
    EXPECT_EQ(got, payload);

    pub->stop();
    sub->stop();
}

#endif  // FB_HAVE_PAHO
