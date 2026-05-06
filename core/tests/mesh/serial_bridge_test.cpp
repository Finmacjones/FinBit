// SPDX-License-Identifier: AGPL-3.0-or-later
// Serial-bridge end-to-end test using a real PTY pair created in-process
// via posix_openpt(). The SerialBridge opens the slave end; the test reads
// and writes the master end directly to simulate a companion node.

#include "fb/mesh/bridge.hpp"

#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

struct PtyPair {
    int   master_fd  = -1;
    std::string slave_name;
    PtyPair() {
        master_fd = ::posix_openpt(O_RDWR | O_NOCTTY);
        if (master_fd < 0) throw std::runtime_error("posix_openpt failed");
        if (::grantpt(master_fd) < 0 || ::unlockpt(master_fd) < 0) {
            ::close(master_fd);
            master_fd = -1;
            throw std::runtime_error("grantpt/unlockpt failed");
        }
        const char* name = ::ptsname(master_fd);
        if (!name) {
            ::close(master_fd);
            master_fd = -1;
            throw std::runtime_error("ptsname failed");
        }
        slave_name = name;
    }
    ~PtyPair() {
        if (master_fd >= 0) ::close(master_fd);
    }
};

// Write a length-prefixed frame to the master side (so the bridge sees a
// complete frame on its slave-side read).
void write_frame_to_master(int master_fd, std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> framed;
    framed.reserve(2 + payload.size());
    framed.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xff));
    framed.push_back(static_cast<std::uint8_t>(payload.size() & 0xff));
    framed.insert(framed.end(), payload.begin(), payload.end());
    std::size_t off = 0;
    while (off < framed.size()) {
        const ssize_t n = ::write(master_fd, framed.data() + off, framed.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            FAIL() << "write to PTY master failed: " << std::strerror(errno);
        }
        off += static_cast<std::size_t>(n);
    }
}

// Read frames from master until we see one (or timeout). Returns its payload.
std::vector<std::uint8_t> read_frame_from_master(int master_fd, int timeout_ms) {
    std::vector<std::uint8_t> buf;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::array<std::uint8_t, 256> chunk{};
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        if (remaining <= 0) break;
        timeval tv{};
        tv.tv_sec = remaining / 1'000'000;
        tv.tv_usec = remaining % 1'000'000;
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(master_fd, &rs);
        const int sel = ::select(master_fd + 1, &rs, nullptr, nullptr, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            return {};
        }
        if (sel == 0) continue;
        const ssize_t n = ::read(master_fd, chunk.data(), chunk.size());
        if (n <= 0) continue;
        buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
        if (buf.size() < 2) continue;
        const std::size_t len = (static_cast<std::size_t>(buf[0]) << 8) |
                                static_cast<std::size_t>(buf[1]);
        if (buf.size() >= 2 + len) {
            return std::vector<std::uint8_t>(buf.begin() + 2, buf.begin() + 2 + len);
        }
    }
    return {};
}

}  // namespace

TEST(SerialBridge, DeviceToHostFrameFlow) {
    PtyPair pty;
    auto bridge = fb::mesh::make_serial_bridge(pty.slave_name, 115200);
    ASSERT_NE(bridge, nullptr);

    std::mutex mu;
    std::condition_variable cv;
    std::vector<std::uint8_t> got;
    bool received = false;
    bridge->set_on_frame([&](const fb::mesh::MeshFrame& f) {
        std::lock_guard lk(mu);
        got = f.payload;
        received = true;
        cv.notify_all();
    });

    ASSERT_TRUE(bridge->start());

    const std::vector<std::uint8_t> payload = {'h', 'e', 'l', 'l', 'o', '-', 'm', 'e', 's', 'h'};
    write_frame_to_master(pty.master_fd,
                          std::span<const std::uint8_t>(payload.data(), payload.size()));

    {
        std::unique_lock lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2), [&] { return received; }));
    }
    EXPECT_EQ(got, payload);

    bridge->stop();
}

TEST(SerialBridge, HostToDeviceFrameFlow) {
    PtyPair pty;
    auto bridge = fb::mesh::make_serial_bridge(pty.slave_name, 115200);
    ASSERT_NE(bridge, nullptr);
    bridge->set_on_frame([](const fb::mesh::MeshFrame&) {});
    ASSERT_TRUE(bridge->start());

    const std::vector<std::uint8_t> payload = {'p', 'i', 'n', 'g'};
    EXPECT_TRUE(bridge->send("primary",
                             std::span<const std::uint8_t>(payload.data(), payload.size())));
    auto got = read_frame_from_master(pty.master_fd, 2000);
    EXPECT_EQ(got, payload);
    bridge->stop();
}
