// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/mesh/bridge.hpp"

#include <fcntl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// =============================================================================
// Serial mesh bridge — POSIX termios.
//
// Wire framing: each direction is a stream of length-prefixed payloads:
//   [u16 BE length][N bytes payload]
//
// `payload` is a serialized MeshFrame protobuf (when production) or, for the
// Phase 4 simplified loopback used by tools/mesh-loopback/loopback.py, a
// plain UTF-8 chat token. The bridge does not interpret the payload bytes
// itself — it just hands them to the OnMeshFrame callback.
//
// Production-grade integration with real Meshtastic / MeshCore companion
// nodes: those devices speak protobuf-over-serial with a 4-byte sync header
// (0x94 0xc3 LEN_HI LEN_LO) per the Meshtastic ServiceEnvelope spec. Wiring
// that decoder in is mechanical; left for the moment we have a real device on
// CI.
// =============================================================================

namespace fb::mesh {
namespace {

speed_t to_speed(std::uint32_t baud) {
    switch (baud) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
        case 460800: return B460800;
        case 921600: return B921600;
        default: return B115200;
    }
}

class SerialBridge final : public IBridge {
public:
    SerialBridge(std::string path, std::uint32_t baud) : path_(std::move(path)), baud_(baud) {}
    ~SerialBridge() override { stop(); }

    bool start() override {
        fd_ = ::open(path_.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd_ < 0) {
            last_error_ = std::string("open(") + path_ + "): " + std::strerror(errno);
            return false;
        }
        termios tio{};
        if (tcgetattr(fd_, &tio) < 0) {
            last_error_ = std::string("tcgetattr: ") + std::strerror(errno);
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        cfmakeraw(&tio);
        cfsetispeed(&tio, to_speed(baud_));
        cfsetospeed(&tio, to_speed(baud_));
        tio.c_cflag |= CLOCAL | CREAD;
        tio.c_cflag &= ~CSTOPB;
        tio.c_cflag &= ~PARENB;
        tio.c_cflag &= ~CSIZE;
        tio.c_cflag |= CS8;
        tio.c_cc[VMIN] = 0;
        tio.c_cc[VTIME] = 0;
        if (tcsetattr(fd_, TCSANOW, &tio) < 0) {
            last_error_ = std::string("tcsetattr: ") + std::strerror(errno);
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        running_ = true;
        reader_ = std::thread([this]() { read_loop(); });
        return true;
    }

    void stop() override {
        running_ = false;
        if (reader_.joinable()) reader_.join();
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    void set_on_frame(OnMeshFrame cb) override {
        std::lock_guard lk(cb_mu_);
        on_frame_ = std::move(cb);
    }

    bool send(const std::string& topic, std::span<const std::uint8_t> payload) override {
        if (fd_ < 0) return false;
        if (payload.size() > 0xFFFF) return false;
        // Frame: [u16 BE length][bytes...]
        std::vector<std::uint8_t> framed;
        framed.reserve(2 + payload.size());
        framed.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xff));
        framed.push_back(static_cast<std::uint8_t>(payload.size() & 0xff));
        framed.insert(framed.end(), payload.begin(), payload.end());
        std::lock_guard lk(write_mu_);
        std::size_t off = 0;
        while (off < framed.size()) {
            const ssize_t n = ::write(fd_, framed.data() + off, framed.size() - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    timeval tv{};
                    tv.tv_sec = 1;
                    fd_set ws;
                    FD_ZERO(&ws);
                    FD_SET(fd_, &ws);
                    const int sel = ::select(fd_ + 1, nullptr, &ws, nullptr, &tv);
                    if (sel <= 0) return false;
                    continue;
                }
                return false;
            }
            off += static_cast<std::size_t>(n);
        }
        (void)topic;  // Phase 0 simplification: single topic per device
        return true;
    }

    [[nodiscard]] const std::string& last_error() const noexcept { return last_error_; }

private:
    void read_loop() {
        std::vector<std::uint8_t> buf;
        std::array<std::uint8_t, 512> chunk{};
        while (running_) {
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 100'000;  // 100ms poll
            fd_set rs;
            FD_ZERO(&rs);
            FD_SET(fd_, &rs);
            const int sel = ::select(fd_ + 1, &rs, nullptr, nullptr, &tv);
            if (sel < 0) {
                if (errno == EINTR) continue;
                return;
            }
            if (sel == 0) continue;
            const ssize_t n = ::read(fd_, chunk.data(), chunk.size());
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                return;
            }
            if (n == 0) continue;
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
            for (;;) {
                if (buf.size() < 2) break;
                const std::size_t len = (static_cast<std::size_t>(buf[0]) << 8) |
                                        static_cast<std::size_t>(buf[1]);
                if (buf.size() < 2 + len) break;
                std::vector<std::uint8_t> payload(buf.begin() + 2, buf.begin() + 2 + len);
                buf.erase(buf.begin(), buf.begin() + 2 + len);
                MeshFrame mf;
                mf.origin = "serial";
                mf.topic = "primary";
                mf.payload = std::move(payload);
                std::lock_guard lk(cb_mu_);
                if (on_frame_) on_frame_(mf);
            }
        }
    }

    std::string path_;
    std::uint32_t baud_;
    int fd_ = -1;
    std::atomic_bool running_{false};
    std::thread reader_;
    std::mutex write_mu_;
    std::mutex cb_mu_;
    OnMeshFrame on_frame_;
    std::string last_error_;
};

}  // namespace

std::unique_ptr<IBridge> make_serial_bridge(const std::string& device_path, std::uint32_t baud) {
    return std::make_unique<SerialBridge>(device_path, baud);
}

}  // namespace fb::mesh
