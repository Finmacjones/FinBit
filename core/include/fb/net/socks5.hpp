// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// SOCKS5 outbound transport (RFC 1928) — for routing FinBit traffic through a
// local proxy such as Tor on 127.0.0.1:9050. Combined with Tor bridges
// (obfs4 / Snowflake) configured in torrc, this lets the client reach a relay
// from networks that DPI-block or whitelist-only the public internet:
//   FinBit  ──TCP──▶  127.0.0.1:9050 (Tor SOCKS5)
//                    └──obfs4 / Snowflake──▶  Tor circuit  ──▶  relay
//
// Wire format (RFC 1928 no-auth CONNECT):
//   greeting:   [05][01][00]                       — VER, NMETHODS, METHODS
//   greet rsp:  [05][METHOD]                       — METHOD=00 ok, FF reject
//   connect:    [05][01][00][ATYP][ADDR…][PORT BE] — CMD=01 CONNECT
//   conn rsp:   [05][REP][00][ATYP][BND…][PORT BE] — REP=00 ok
//
// We always send ATYP=0x03 (domain) so the proxy resolves the hostname — no
// client-side DNS leak (essential for Tor; also lets .onion targets work).
// Pure encode/parse helpers are split out so the wire format is unit-testable
// without a live proxy.
// =============================================================================

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "fb/net/tcp.hpp"

namespace fb::net::socks5 {

// SOCKS5 reply codes (RFC 1928 §6) — surfaced via SocksError.
enum class Rep : std::uint8_t {
    kSucceeded            = 0x00,
    kGeneralFailure       = 0x01,
    kNotAllowed           = 0x02,
    kNetworkUnreachable   = 0x03,
    kHostUnreachable      = 0x04,
    kConnectionRefused    = 0x05,
    kTtlExpired           = 0x06,
    kCommandNotSupported  = 0x07,
    kAddrTypeNotSupported = 0x08,
};

const char* rep_to_string(Rep r) noexcept;

// Thrown by socks5_connect on any handshake failure.
class SocksError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ---- Pure wire-format helpers (unit-testable) -----------------------------

// "[0x05][0x01][0x00]" — no-auth greeting.
[[nodiscard]] std::vector<std::uint8_t> encode_greeting();

// Returns the server's chosen METHOD byte if the response is well-formed
// (VER=0x05, exactly 2 bytes); std::nullopt otherwise. 0x00 = NO_AUTH accepted;
// 0xFF = no acceptable method.
[[nodiscard]] std::optional<std::uint8_t> parse_greeting_response(
    std::span<const std::uint8_t> resp);

// CONNECT request with ATYP=0x03 (domain). host must be 1..255 bytes.
[[nodiscard]] std::vector<std::uint8_t> encode_connect_request(
    const std::string& host, std::uint16_t port);

// How many bytes the CONNECT response will be GIVEN the ATYP byte. The reply
// format is [VER][REP][RSV][ATYP][BND.ADDR…][BND.PORT BE u16]; the address
// length depends on ATYP. Returns std::nullopt for an unknown ATYP.
//   0x01 (IPv4)   →  4+2+4 = 10 total bytes (incl. the 4 header bytes)
//   0x03 (domain) →  4 + 1 + name_len + 2 — caller must read the 5th byte
//                    first to learn name_len; this helper returns the tail
//                    length only (name_len + 2). For domain, pass the
//                    domain-length byte.
//   0x04 (IPv6)   →  4+2+16 = 22 total bytes
// For convenience, callers usually read the first 5 bytes (header + first
// addr-byte), then call this with (atyp, first_addr_byte) to learn how many
// more bytes follow.
[[nodiscard]] std::optional<std::size_t> connect_response_tail_len(
    std::uint8_t atyp, std::uint8_t first_addr_byte);

// Parse a complete CONNECT response. Returns the REP code on success, nullopt
// if the payload is malformed (too short, wrong VER, unknown ATYP, etc.).
[[nodiscard]] std::optional<Rep> parse_connect_response(
    std::span<const std::uint8_t> full_response);

// ---- Live transport --------------------------------------------------------

// Dial the SOCKS5 proxy and tunnel a TCP connection to `target_host:port`.
// Returns the proxy-side socket, already non-blocking and ready for the
// caller to layer TLS over (the proxy will splice bytes through to the
// target). Throws SocksError on any handshake failure.
//
// `timeout_ms` bounds the whole handshake (greet + CONNECT round-trips), not
// the lifetime of the resulting tunnel.
[[nodiscard]] fb::net::Socket socks5_connect(
    const std::string& proxy_host, std::uint16_t proxy_port,
    const std::string& target_host, std::uint16_t target_port,
    int timeout_ms = 10000);

}  // namespace fb::net::socks5
