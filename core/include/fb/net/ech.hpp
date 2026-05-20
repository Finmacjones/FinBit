// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Encrypted Client Hello (ECH) config handling — Tier-4 groundwork.
//
// ECH (draft-ietf-tls-esni / RFC-track) encrypts the SNI and the
// sensitive inner ClientHello extensions inside an outer ClientHello
// that names a public/decoy host, using HPKE (RFC 9180) to a key the
// server publishes as an `ECHConfigList`. A relay publishes its
// ECHConfigList — typically in a DNS `HTTPS`/`SVCB` resource record's
// `ech=` parameter, which FinBit can carry over the Tier-1 DoH path —
// and clients feed it to the TLS stack, which performs the actual
// encryption.
//
// STATUS. This module handles the *config* side: base64-decoding and
// validating the ECHConfigList wire format so it can be handed to the
// TLS stack via TlsClientOptions::ech_config_list. The encryption
// itself is the TLS library's job:
//   - OpenSSL 3.6 ships the HPKE primitive (openssl/hpke.h) but not yet
//     the SSL_* ECH handshake hooks, so FB_HAVE_ECH is 0 on it and the
//     wiring compiles to a no-op.
//   - When built against a stack with ECH (a future OpenSSL, or
//     BoringSSL), FB_HAVE_ECH becomes 1 and TlsClient applies the
//     config — encrypting the SNI for real.
// See docs/censorship-resistance.md (Tier 4).
// =============================================================================

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace fb::net::ech {

// Validate the ECHConfigList wire format (draft-ietf-tls-esni):
//
//   ECHConfigList = uint16 length-prefix + sequence of ECHConfig
//   ECHConfig     = uint16 version + uint16 length + length bytes
//
// Returns true iff the 2-byte outer length matches the buffer, every
// inner ECHConfig frames within bounds, and there is at least one
// config. Does NOT interpret the config contents (HPKE keys etc.) —
// that's the TLS stack's job.
[[nodiscard]] bool ech_config_list_looks_valid(
    const std::vector<std::uint8_t>& bytes);

// Decode a base64 ECHConfigList (as published in a DNS `ech=` value /
// FinBit TXT `ech=` token) into raw bytes, validating the framing.
// Returns nullopt on a base64 error or malformed framing.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
decode_ech_config_list_b64(std::string_view b64);

// Scan a FinBit TXT record body for an `ech=<base64>` token and return
// the decoded + validated ECHConfigList, if present and well-formed.
// Tokens are whitespace-separated; anything that isn't a valid ech=
// token is ignored. Returns nullopt when no usable ech= token is found.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
parse_ech_param(std::string_view txt_body);

}  // namespace fb::net::ech
