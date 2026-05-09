// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Username log — append-only signed-claim store binding usernames to Ed25519
// pubkeys. Conflict resolution is deterministic (smallest valid timestamp_ms
// for a given username wins). Eventually consistent: if a peer hands us an
// OLDER claim for a name we already think someone else owns, we accept and
// store it; the resolve() call returns the new (older-timestamp) winner.
//
// This is the directory-layer answer to "what owns the name 'alice' across
// the network", without a blockchain. Same shape as Nostr / Sigstore-Rekor /
// Certificate Transparency: signed events on a replicable log, no consensus.
//
// Storage is delegated to fb::store::SqliteStore via the mls_group_log-style
// per-table API (separate username_claims table; signed claims are public so
// no AEAD wrapping). Verification uses the Ed25519 routines in
// fb::crypto::identity / aead helpers.
//
// API design notes:
//   * append_claim takes a fully-built UserClaim (signature + nonce already
//     populated). For the producer side, build_claim does the canonical
//     serialization + signing in one shot from a private key + chosen
//     username + clock.
//   * resolve(username) returns the CURRENT winner (smallest timestamp_ms).
//     Returns nullopt if no valid claim exists.
//   * usernames_of(pubkey) returns every username this pubkey has ever
//     successfully claimed (in timestamp order). Useful for "show alice's
//     past handles".
//   * claims_since(ts_ms, max) is the gossip read primitive — return at
//     most `max` claims with timestamp_ms > ts_ms, ordered.
// =============================================================================

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fb::store { class SqliteStore; }
namespace fb::proto { class UserClaim; }

namespace fb::identity {

// Maximum permitted clock skew when validating future-timestamped claims.
// Anything more than this far in the future is rejected as nonsense.
constexpr std::uint64_t kAcceptedClockSkewMs = 5 * 60 * 1000;   // 5 minutes

// Min/max byte length of the username field (UTF-8 bytes, NOT codepoints).
constexpr std::size_t kUsernameMinBytes = 3;
constexpr std::size_t kUsernameMaxBytes = 32;

// Accepted ASCII charset for usernames in the v0 namespace. Lowercase
// letters, digits, and three punctuation chars. Wider Unicode is reserved
// for a later namespace; today's restriction makes server-log inspection
// and CLI argv handling unambiguous.
bool is_valid_username(std::string_view candidate);

// Canonical-form serializer used both at signing and at verification time.
// The signature covers exactly these bytes — calling code MUST NOT
// re-marshal via tls::marshal or protobuf SerializeToString and expect
// agreement. This shape pins (username || pubkey || timestamp_ms ||
// nonce) into a deterministic byte string regardless of protobuf wire
// quirks (field ordering, varint canonicalization, etc.).
std::vector<std::uint8_t> canonical_signing_bytes(
    std::string_view username,
    std::span<const std::uint8_t> pubkey,
    std::uint64_t timestamp_ms,
    std::span<const std::uint8_t> nonce);

// Build + sign a claim. Returns a UserClaim ready for append_claim or
// gossip. Throws std::invalid_argument on malformed username or wrong
// keypair length.
fb::proto::UserClaim build_claim(
    std::string_view username,
    std::span<const std::uint8_t> sig_pub,    // 32B Ed25519 public key
    std::span<const std::uint8_t> sig_priv,   // 64B Ed25519 secret key
    std::uint64_t timestamp_ms);

class UsernameLog {
public:
    // The store must outlive this UsernameLog. The log uses the store's
    // username_claims table (created lazily on first construction).
    explicit UsernameLog(fb::store::SqliteStore& store);
    ~UsernameLog();

    UsernameLog(const UsernameLog&) = delete;
    UsernameLog& operator=(const UsernameLog&) = delete;

    enum class AppendResult {
        kAccepted,        // Claim is valid + new (or supersedes by older ts).
        kAlreadyKnown,    // Exact (username, pubkey) already in log; no-op.
        kRejectedFormat,  // Username fails is_valid_username, or sizes wrong.
        kRejectedSig,     // Signature didn't verify.
        kRejectedClock,   // timestamp_ms more than kAcceptedClockSkewMs in
                          // the future relative to now_ms (or wall-clock).
    };

    // Validate + insert a claim. Idempotent on the (username, pubkey) pair
    // — the same exact claim can be appended twice with no effect.
    // `now_ms` is the current wall-clock time in ms; pass 0 to use the
    // system clock automatically.
    AppendResult append_claim(const fb::proto::UserClaim& claim,
                               std::uint64_t now_ms = 0);

    // Resolve a username to its current winning pubkey. Returns nullopt if
    // no valid claim exists for the username.
    [[nodiscard]] std::optional<std::array<std::uint8_t, 32>> resolve(
        std::string_view username) const;

    // Return every username this pubkey has successfully claimed, ordered
    // by timestamp_ms ASC. May include usernames the pubkey is NOT the
    // current winner for (someone else holds an older claim).
    [[nodiscard]] std::vector<std::string> usernames_of(
        std::span<const std::uint8_t> pubkey) const;

    // Gossip read: return up to `max` claims with timestamp_ms strictly
    // greater than `since_ms`, ordered ascending by timestamp_ms.
    [[nodiscard]] std::vector<fb::proto::UserClaim> claims_since(
        std::uint64_t since_ms, std::size_t max) const;

    // Diagnostics.
    [[nodiscard]] std::size_t total_claims() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::identity
