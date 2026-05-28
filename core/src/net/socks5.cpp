// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/socks5.hpp"

#include <cstring>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using socklen_t = int;
   static inline int  fb_send(int s, const void* b, std::size_t n) { return ::send(s, (const char*)b, (int)n, 0); }
   static inline int  fb_recv(int s, void*       b, std::size_t n) { return ::recv(s, (char*)b,       (int)n, 0); }
   static inline void fb_set_blocking(int s) { u_long mode = 0; ioctlsocket(s, FIONBIO, &mode); }
   static inline void fb_set_nonblocking(int s) { u_long mode = 1; ioctlsocket(s, FIONBIO, &mode); }
   static inline void fb_set_rcv_timeout(int s, int ms) {
       DWORD t = (DWORD)ms;
       ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
       ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
   }
#else
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <sys/time.h>
   static inline ssize_t fb_send(int s, const void* b, std::size_t n) { return ::send(s, b, n, 0); }
   static inline ssize_t fb_recv(int s, void*       b, std::size_t n) { return ::recv(s, b, n, 0); }
   static inline void fb_set_blocking(int s) {
       int f = ::fcntl(s, F_GETFL, 0);
       if (f != -1) ::fcntl(s, F_SETFL, f & ~O_NONBLOCK);
   }
   static inline void fb_set_nonblocking(int s) {
       int f = ::fcntl(s, F_GETFL, 0);
       if (f != -1) ::fcntl(s, F_SETFL, f | O_NONBLOCK);
   }
   static inline void fb_set_rcv_timeout(int s, int ms) {
       timeval tv{};
       tv.tv_sec  = ms / 1000;
       tv.tv_usec = (ms % 1000) * 1000;
       ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
       ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
   }
#endif

namespace fb::net::socks5 {

const char* rep_to_string(Rep r) noexcept {
    switch (r) {
        case Rep::kSucceeded:            return "succeeded";
        case Rep::kGeneralFailure:       return "general SOCKS failure";
        case Rep::kNotAllowed:           return "connection not allowed by ruleset";
        case Rep::kNetworkUnreachable:   return "network unreachable";
        case Rep::kHostUnreachable:      return "host unreachable";
        case Rep::kConnectionRefused:    return "connection refused";
        case Rep::kTtlExpired:           return "TTL expired";
        case Rep::kCommandNotSupported:  return "command not supported";
        case Rep::kAddrTypeNotSupported: return "address type not supported";
    }
    return "unknown SOCKS reply";
}

// ---- Pure wire-format helpers --------------------------------------------

std::vector<std::uint8_t> encode_greeting() {
    return {0x05, 0x01, 0x00};   // VER=5, NMETHODS=1, METHODS=[NO_AUTH]
}

std::optional<std::uint8_t> parse_greeting_response(std::span<const std::uint8_t> r) {
    if (r.size() != 2) return std::nullopt;
    if (r[0] != 0x05)  return std::nullopt;
    return r[1];
}

std::vector<std::uint8_t> encode_connect_request(const std::string& host,
                                                 std::uint16_t port) {
    std::vector<std::uint8_t> out;
    out.reserve(7 + host.size());
    out.push_back(0x05);                                       // VER
    out.push_back(0x01);                                       // CMD = CONNECT
    out.push_back(0x00);                                       // RSV
    out.push_back(0x03);                                       // ATYP = domain
    // Domain length-prefixed; cap at 255 (RFC limit). If the caller passes
    // something longer they'll get a truncated address — but no real
    // hostname is anywhere near 255 bytes.
    const std::size_t hlen = host.size() > 255 ? 255 : host.size();
    out.push_back(static_cast<std::uint8_t>(hlen));
    out.insert(out.end(), host.data(), host.data() + hlen);
    out.push_back(static_cast<std::uint8_t>((port >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(port & 0xff));
    return out;
}

std::optional<std::size_t> connect_response_tail_len(std::uint8_t atyp,
                                                     std::uint8_t first_addr_byte) {
    // header (VER REP RSV ATYP) is 4 bytes — already consumed by the caller.
    // Return the remaining length after the 4-byte header.
    switch (atyp) {
        case 0x01: return 4  + 2;                         // IPv4 + port
        case 0x03: return std::size_t(first_addr_byte) + 1 + 2;  // len + name + port
        case 0x04: return 16 + 2;                         // IPv6 + port
        default:   return std::nullopt;
    }
}

std::optional<Rep> parse_connect_response(std::span<const std::uint8_t> r) {
    if (r.size() < 5)  return std::nullopt;   // need ATYP + at least 1 addr byte
    if (r[0] != 0x05)  return std::nullopt;
    if (r[2] != 0x00)  return std::nullopt;   // RSV must be 0
    auto tail = connect_response_tail_len(r[3], r[4]);
    if (!tail)         return std::nullopt;
    if (r.size() < 4 + *tail) return std::nullopt;
    return static_cast<Rep>(r[1]);
}

// ---- Live transport -------------------------------------------------------

namespace {

// Blocking send-all with the SO_SNDTIMEO already set on the fd. Throws on
// short/error (proxy died mid-handshake).
void send_all(int fd, std::span<const std::uint8_t> data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const auto n = fb_send(fd, data.data() + off, data.size() - off);
        if (n <= 0) throw SocksError("SOCKS5: short send during handshake");
        off += static_cast<std::size_t>(n);
    }
}

// Blocking recv-exact with the SO_RCVTIMEO already set. Throws on short/EOF.
void recv_exact(int fd, std::span<std::uint8_t> out) {
    std::size_t off = 0;
    while (off < out.size()) {
        const auto n = fb_recv(fd, out.data() + off, out.size() - off);
        if (n <= 0) throw SocksError("SOCKS5: short recv during handshake "
                                     "(proxy unreachable or closed)");
        off += static_cast<std::size_t>(n);
    }
}

}  // namespace

fb::net::Socket socks5_connect(const std::string& proxy_host,
                                std::uint16_t proxy_port,
                                const std::string& target_host,
                                std::uint16_t target_port,
                                int timeout_ms) {
    if (target_host.empty() || target_host.size() > 255) {
        throw SocksError("SOCKS5: target host must be 1..255 bytes");
    }

    // 1. Connect to the proxy (gets a non-blocking socket).
    fb::net::Socket s = fb::net::tcp_connect(proxy_host, proxy_port);
    if (!s.valid()) throw SocksError("SOCKS5: tcp_connect to proxy failed");

    // 2. Switch to blocking with a timeout for the brief handshake. After we
    //    return, the caller's TLS layer expects a non-blocking socket — flip
    //    back below.
    fb_set_blocking(s.fd());
    fb_set_rcv_timeout(s.fd(), timeout_ms);

    // 3. Greeting: offer NO_AUTH.
    send_all(s.fd(), encode_greeting());
    std::uint8_t greet_resp[2];
    recv_exact(s.fd(), std::span<std::uint8_t>(greet_resp, 2));
    auto method = parse_greeting_response(
        std::span<const std::uint8_t>(greet_resp, 2));
    if (!method) throw SocksError("SOCKS5: malformed greeting response");
    if (*method != 0x00) {
        throw SocksError("SOCKS5: proxy rejected NO_AUTH "
                         "(method 0xFF means no acceptable methods)");
    }

    // 4. CONNECT (domain ATYP — proxy resolves; no client DNS leak).
    send_all(s.fd(), encode_connect_request(target_host, target_port));
    // Read header + first addr byte (5 bytes) so we can size the tail.
    std::uint8_t hdr[5];
    recv_exact(s.fd(), std::span<std::uint8_t>(hdr, 5));
    if (hdr[0] != 0x05 || hdr[2] != 0x00) {
        throw SocksError("SOCKS5: malformed CONNECT response header");
    }
    if (hdr[1] != 0x00) {
        const auto rep = static_cast<Rep>(hdr[1]);
        throw SocksError(std::string("SOCKS5 CONNECT refused: ") +
                         rep_to_string(rep));
    }
    auto tail = connect_response_tail_len(hdr[3], hdr[4]);
    if (!tail) throw SocksError("SOCKS5: unknown ATYP in CONNECT response");
    if (*tail > 1) {
        std::vector<std::uint8_t> rest(*tail - 1);   // first addr byte already read
        recv_exact(s.fd(), std::span<std::uint8_t>(rest.data(), rest.size()));
    }

    // 5. Tunnel is open. Restore non-blocking; clear handshake timeouts.
    fb_set_nonblocking(s.fd());
    fb_set_rcv_timeout(s.fd(), 0);   // 0 = no timeout
    return s;
}

}  // namespace fb::net::socks5
