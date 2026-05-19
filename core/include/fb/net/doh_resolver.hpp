// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// DNS-over-HTTPS (DoH) bootstrap resolver — censorship-resistance layer.
//
// The first-run problem in any P2P system is finding ONE peer. A
// file-based bootstrap list (bootstrap.txt) works when the user has
// fetched it via some channel, but on a hostile network the act of
// FETCHING the bootstrap is itself a censorship choke-point — a
// plain `dig <host>` reveals the lookup; a fetch of `bootstrap.txt`
// from a known server reveals the destination.
//
// DoH defeats both: the lookup is a normal HTTPS request to a
// well-known public DoH endpoint (Cloudflare's `cloudflare-dns.com`
// or Google's `dns.google`). A censor would have to either block
// every public DoH provider (would break a large fraction of
// legitimate HTTPS-using clients) or block all of port 443 (would
// break the entire web).
//
// Wire format. We piggyback on standard DNS TXT records, namespaced
// under the `_finbit` label. Operators publish their bootstrap peers
// as:
//
//   _finbit.example.com  IN  TXT  "fb1 ed25519:<hex32> wss://relay.example.com:443[#<sha256fp>]"
//
// Multiple TXT records under the same name are allowed and
// recommended — the resolver returns ALL of them so the routing
// table can dial whichever is reachable. The `fb1` prefix
// future-proofs the format; unknown prefixes are skipped silently.
//
// Threat model. We defend against:
//   * Plain-DNS sniffing (DoH is HTTPS-only, looks like a normal
//     web fetch to a passive observer).
//   * Bootstrap-IP blocking (TXT records can list multiple peers
//     with rotating addresses; the operator updates DNS, no code
//     change needed).
//
// We do NOT defend against:
//   * TLS fingerprinting (JA3) — OpenSSL's ClientHello is identifiable
//     even on port 443. uTLS-style mimicry is queued for a later
//     release.
//   * Blocking the DoH endpoint by IP — if Cloudflare's
//     1.1.1.1 / cloudflare-dns.com is hard-blocked, the resolver
//     fails. Mitigation: try multiple endpoints in fallback order.
//   * Traffic timing / volume analysis.
//
// See docs/censorship-resistance.md for the full threat model.
// =============================================================================

#include "fb/p2p/kademlia.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fb::net {

// One DoH resolver endpoint. Default endpoints:
//   - Cloudflare:   https://cloudflare-dns.com/dns-query
//   - Google:       https://dns.google/resolve
//   - Quad9:        https://dns.quad9.net:5053/dns-query
// All accept the `application/dns-json` content-type used here.
struct DohEndpoint {
    std::string host;        // e.g. "cloudflare-dns.com"
    std::uint16_t port = 443;
    std::string path;        // e.g. "/dns-query" or "/resolve"
    // Optional pinned cert SHA-256 fingerprint (binary, 32 bytes).
    // If non-empty, the TLS handshake against this DoH endpoint
    // must present a leaf cert whose SHA-256 matches.
    std::vector<std::uint8_t> pinned_sha256;
};

// Sensible defaults. Resolvers should fall through this list if any
// individual endpoint fails (blocked, timed out, returned no answer).
[[nodiscard]] std::vector<DohEndpoint> default_doh_endpoints();

// Parse a TXT record body into a BootstrapPeer. Returns nullopt if the
// body doesn't start with "fb1 " or doesn't match the
//   "fb1 ed25519:<64-hex> <addr>"
// grammar. Public for testability.
[[nodiscard]] std::optional<fb::p2p::PeerInfo>
parse_finbit_txt(std::string_view txt_body);

// Parse a Cloudflare/Google application/dns-json response body. Looks
// at the "Answer" array, pulls out TXT-shaped entries (type == 16),
// strips the wire-protocol length-prefix bytes ("\NN..." → "..."),
// and runs parse_finbit_txt over each. Returns the union of valid
// FinBit-shaped peers. Public for testability.
[[nodiscard]] std::vector<fb::p2p::PeerInfo>
parse_dns_json(std::string_view body);

// Make a single DoH GET request and return the list of FinBit peer
// records found. Blocking, with `timeout_ms` budget for the whole
// HTTPS round-trip (connect + handshake + request + response). Returns
// an empty vector on any failure (network, TLS, HTTP non-200,
// JSON parse, no Answer section, etc.).
[[nodiscard]] std::vector<fb::p2p::PeerInfo>
resolve_finbit_bootstrap(
    const DohEndpoint& endpoint,
    std::string_view query_name,
    int timeout_ms);

// Walk the default endpoints in order and return the first endpoint
// that returned at least one peer record. Use this as the high-level
// entry point in client startup.
[[nodiscard]] std::vector<fb::p2p::PeerInfo>
resolve_finbit_bootstrap_default(
    std::string_view query_name,
    int per_endpoint_timeout_ms = 5000);

}  // namespace fb::net
