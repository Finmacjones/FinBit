// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Bootstrap-list loader.
//
// First-run problem in any P2P system: we need to find AT LEAST ONE peer to
// kick off DHT lookups + gossip syncs. After that, peer-exchange does the
// rest. The bootstrap list provides the seed.
//
// File format (one peer per line, "#" comments + blank lines ignored):
//
//     <hex-pubkey-32-bytes>  <addr>
//
// Example:
//
//     # FinBit Phase-5 bootstrap, last refreshed 2026-05-09
//     6fa3...c19e  wss://bootstrap-1.finbit.example:443
//     b801...44df  wss://bootstrap-2.finbit.example:443
//     dead...beef  tcp://203.0.113.5:8765
//
// Each entry produces a fb::p2p::PeerInfo with id =
// node_id_from_pubkey(pubkey), pubkey populated, addr verbatim. Caller hands
// the vector to RoutingTable.observe(...) on each.
//
// Default file paths searched (in order):
//   $FB_BOOTSTRAP_FILE                 — env var override
//   $XDG_CONFIG_HOME/finbit/bootstrap.txt
//   $HOME/.finbit/bootstrap.txt
//   /etc/finbit/bootstrap.txt
//
// The default search is opt-in: callers either pass an explicit path or call
// load_default_bootstrap() which returns an empty vector when nothing
// matches (i.e. peers will only show up via runtime peer-exchange or via
// inbound traffic from the central server).
// =============================================================================

#include "fb/p2p/kademlia.hpp"

#include <string>
#include <vector>

namespace fb::p2p {

// Parse the contents of a bootstrap file in memory. Skips blank lines
// and comments (lines starting with #). Tolerates malformed lines —
// they're skipped and counted; caller can check the failure_count
// out-param if it cares.
struct BootstrapParseResult {
    std::vector<PeerInfo>     peers;
    std::size_t               malformed_lines = 0;
};
[[nodiscard]] BootstrapParseResult parse_bootstrap_text(
    const std::string& contents);

// Read + parse a file. Throws std::runtime_error on open() failure.
// Returns an empty BootstrapParseResult for an empty file.
[[nodiscard]] BootstrapParseResult load_bootstrap_file(
    const std::string& path);

// Walks the default search list (FB_BOOTSTRAP_FILE / XDG /
// $HOME/.finbit / /etc/finbit) and loads the first file that exists.
// Returns an empty result if none are present. Never throws — missing
// or malformed paths are treated as "no bootstrap data".
[[nodiscard]] BootstrapParseResult load_default_bootstrap();

// =============================================================================
// DoH bootstrap (censorship-resistance layer).
//
// Resolves peers via DNS-over-HTTPS TXT records under the `_finbit.`
// prefix. The wire format for each TXT body matches the file-based
// bootstrap line format:
//
//     fb1 ed25519:<hex32> <addr>
//
// Example DNS zone snippet:
//
//     _finbit.example.com.  300  IN  TXT  "fb1 ed25519:6fa3...c19e wss://relay-1.example.com:443"
//     _finbit.example.com.  300  IN  TXT  "fb1 ed25519:b801...44df wss://relay-2.example.com:443"
//
// All TXT records under the same name are returned (the routing
// table picks whichever is reachable).
//
// The DoH lookup is HTTPS-only to Cloudflare/Google/Quad9 — looks
// like normal browser traffic to a passive observer. See
// docs/censorship-resistance.md.
//
// Env var: FB_BOOTSTRAP_DOH=<query-name> drives this. Empty / unset
// means no DoH lookup.
// =============================================================================

// Driven by FB_BOOTSTRAP_DOH. If the env var is unset/empty OR the
// build doesn't have OpenSSL (FB_HAVE_OPENSSL=0), returns an empty
// result. Never throws.
[[nodiscard]] BootstrapParseResult load_doh_bootstrap();

// Convenience: returns the UNION of load_default_bootstrap() (file)
// and load_doh_bootstrap() (DNS-over-HTTPS). Duplicate peer pubkeys
// from both sources are de-duplicated. This is the entry-point most
// clients should call at startup.
[[nodiscard]] BootstrapParseResult load_default_bootstrap_all();

}  // namespace fb::p2p
