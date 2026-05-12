// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/mesh/bridge.hpp"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <array>
#  include <fcntl.h>
#  include <sys/select.h>
#  include <termios.h>
#  include <unistd.h>
#endif

// =============================================================================
// Serial mesh bridge — cross-platform.
//
// POSIX: termios + select(read).
// Windows: CreateFile("\\\\.\\COMx") + DCB + COMMTIMEOUTS (synchronous I/O
// with a 100 ms total read timeout, matching the POSIX select(timeout=100ms)
// poll cadence).
//
// Wire framing: each direction is a stream of length-prefixed payloads:
//   [u16 BE length][N bytes payload]
//
// `payload` is a serialized MeshFrame protobuf (production) or, for the
// Phase 4 simplified loopback used by tools/mesh-loopback/loopback.py, a
// plain UTF-8 chat token. The bridge does not interpret the payload bytes
// itself — it just hands them to the OnMeshFrame callback.
// =============================================================================

namespace fb::mesh {
namespace {

#if defined(_WIN32)
// Win32 CreateFile expects "\\.\COM10" form for COM ports >= 10 (and
// also accepts it for COM1..COM9). The caller passes either form; we
// prepend the prefix if it's not already there.
std::string normalise_com_path(const std::string& p) {
    if (p.size() >= 4 && p.compare(0, 4, "\\\\.\\") == 0) return p;
    return "\\\\.\\" + p;
}
#else
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
#endif

class SerialBridge final : public IBridge {
public:
    SerialBridge(std::string path, std::uint32_t baud)
        : path_(std::move(path)), baud_(baud) {}
    ~SerialBridge() override { stop(); }

    bool start() override {
#if defined(_WIN32)
        const std::string winp = normalise_com_path(path_);
        handle_ = ::CreateFileA(winp.c_str(),
                                 GENERIC_READ | GENERIC_WRITE,
                                 0,        // exclusive access
                                 nullptr,  // default security
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            last_error_ = "CreateFile(" + path_ + "): " +
                          std::to_string(::GetLastError());
            return false;
        }
        DCB dcb{};
        dcb.DCBlength = sizeof(dcb);
        if (!::GetCommState(handle_, &dcb)) {
            last_error_ = "GetCommState: " +
                          std::to_string(::GetLastError());
            ::CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE;
            return false;
        }
        dcb.BaudRate         = baud_;
        dcb.ByteSize         = 8;
        dcb.Parity           = NOPARITY;
        dcb.StopBits         = ONESTOPBIT;
        dcb.fBinary          = TRUE;
        dcb.fParity          = FALSE;
        dcb.fOutxCtsFlow     = FALSE;
        dcb.fOutxDsrFlow     = FALSE;
        dcb.fDtrControl      = DTR_CONTROL_DISABLE;
        dcb.fDsrSensitivity  = FALSE;
        dcb.fTXContinueOnXoff = FALSE;
        dcb.fOutX            = FALSE;
        dcb.fInX             = FALSE;
        dcb.fErrorChar       = FALSE;
        dcb.fNull            = FALSE;
        dcb.fRtsControl      = RTS_CONTROL_DISABLE;
        dcb.fAbortOnError    = FALSE;
        if (!::SetCommState(handle_, &dcb)) {
            last_error_ = "SetCommState: " +
                          std::to_string(::GetLastError());
            ::CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE;
            return false;
        }
        // 100 ms total read timeout matches the POSIX 100 ms select
        // poll. ReadIntervalTimeout=MAXDWORD + Multiplier=0 +
        // Constant=100 means "wait up to 100ms for data; if any
        // arrives, return immediately".
        COMMTIMEOUTS to{};
        to.ReadIntervalTimeout         = MAXDWORD;
        to.ReadTotalTimeoutMultiplier  = 0;
        to.ReadTotalTimeoutConstant    = 100;
        to.WriteTotalTimeoutMultiplier = 0;
        to.WriteTotalTimeoutConstant   = 1000;
        if (!::SetCommTimeouts(handle_, &to)) {
            last_error_ = "SetCommTimeouts: " +
                          std::to_string(::GetLastError());
            ::CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE;
            return false;
        }
        running_ = true;
        reader_ = std::thread([this]() { read_loop(); });
        return true;
#else
        fd_ = ::open(path_.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd_ < 0) {
            last_error_ = std::string("open(") + path_ + "): " + std::strerror(errno);
            return false;
        }
        termios tio{};
        if (tcgetattr(fd_, &tio) < 0) {
            last_error_ = std::string("tcgetattr: ") + std::strerror(errno);
            ::close(fd_); fd_ = -1;
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
        tio.c_cc[VMIN]  = 0;
        tio.c_cc[VTIME] = 0;
        if (tcsetattr(fd_, TCSANOW, &tio) < 0) {
            last_error_ = std::string("tcsetattr: ") + std::strerror(errno);
            ::close(fd_); fd_ = -1;
            return false;
        }
        running_ = true;
        reader_ = std::thread([this]() { read_loop(); });
        return true;
#endif
    }

    void stop() override {
        running_ = false;
        if (reader_.joinable()) reader_.join();
#if defined(_WIN32)
        if (handle_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
#endif
    }

    void set_on_frame(OnMeshFrame cb) override {
        std::lock_guard lk(cb_mu_);
        on_frame_ = std::move(cb);
    }

    bool send(const std::string& topic,
              std::span<const std::uint8_t> payload) override {
#if defined(_WIN32)
        if (handle_ == INVALID_HANDLE_VALUE) return false;
#else
        if (fd_ < 0) return false;
#endif
        if (payload.size() > 0xFFFF) return false;
        std::vector<std::uint8_t> framed;
        framed.reserve(2 + payload.size());
        framed.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xff));
        framed.push_back(static_cast<std::uint8_t>(payload.size() & 0xff));
        framed.insert(framed.end(), payload.begin(), payload.end());
        std::lock_guard lk(write_mu_);
#if defined(_WIN32)
        DWORD written = 0;
        if (!::WriteFile(handle_, framed.data(),
                          static_cast<DWORD>(framed.size()),
                          &written, nullptr) ||
            written != framed.size()) {
            return false;
        }
        (void)topic;
        return true;
#else
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
        (void)topic;
        return true;
#endif
    }

    [[nodiscard]] const std::string& last_error() const noexcept { return last_error_; }

private:
    void read_loop() {
        std::vector<std::uint8_t> buf;
#if defined(_WIN32)
        std::vector<std::uint8_t> chunk(512);
        while (running_) {
            DWORD got = 0;
            // ReadFile honours SetCommTimeouts — returns within ~100 ms
            // even if no data arrived. got=0 means timeout; no error.
            const BOOL ok = ::ReadFile(handle_, chunk.data(),
                                        static_cast<DWORD>(chunk.size()),
                                        &got, nullptr);
            if (!ok) {
                const DWORD err = ::GetLastError();
                // ERROR_OPERATION_ABORTED fires when stop() closes
                // the handle from another thread; treat as clean exit.
                if (err == ERROR_OPERATION_ABORTED) return;
                continue;
            }
            if (got == 0) continue;   // timeout, try again
            buf.insert(buf.end(), chunk.begin(),
                        chunk.begin() + static_cast<std::ptrdiff_t>(got));
            drain_frames(buf);
        }
#else
        std::array<std::uint8_t, 512> chunk{};
        while (running_) {
            timeval tv{};
            tv.tv_sec  = 0;
            tv.tv_usec = 100'000;     // 100 ms poll
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
            drain_frames(buf);
        }
#endif
    }

    // Pull complete [u16 BE len][bytes] frames out of `buf` and
    // dispatch them via on_frame_. Shared between both backends so
    // the framing logic isn't duplicated.
    void drain_frames(std::vector<std::uint8_t>& buf) {
        for (;;) {
            if (buf.size() < 2) break;
            const std::size_t len =
                (static_cast<std::size_t>(buf[0]) << 8) |
                 static_cast<std::size_t>(buf[1]);
            if (buf.size() < 2 + len) break;
            std::vector<std::uint8_t> payload(
                buf.begin() + 2,
                buf.begin() + 2 + static_cast<std::ptrdiff_t>(len));
            buf.erase(buf.begin(),
                      buf.begin() + 2 + static_cast<std::ptrdiff_t>(len));
            MeshFrame mf;
            mf.origin  = "serial";
            mf.topic   = "primary";
            mf.payload = std::move(payload);
            std::lock_guard lk(cb_mu_);
            if (on_frame_) on_frame_(mf);
        }
    }

    std::string path_;
    std::uint32_t baud_;
#if defined(_WIN32)
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
    std::atomic_bool running_{false};
    std::thread reader_;
    std::mutex write_mu_;
    std::mutex cb_mu_;
    OnMeshFrame on_frame_;
    std::string last_error_;
};

}  // namespace

std::unique_ptr<IBridge> make_serial_bridge(const std::string& device_path,
                                             std::uint32_t baud) {
    return std::make_unique<SerialBridge>(device_path, baud);
}

}  // namespace fb::mesh
