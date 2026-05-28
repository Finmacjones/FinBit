// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// DHT provider record store.
//
// In a Kademlia DHT, a "provider record" is the answer to "where is peer X
// right now?". This file is the FinBit-shaped record store: signed
// (publisher_pubkey, addresses, ttl) bindings keyed by publisher pubkey,
// merged in-memory across whatever records arrive via gossip / direct
// publish.
//
// Storage is ephemeral by design — DHT records are short-lived and meant
// to be re-published periodically by the responsible peer. Persisting
// stale records on restart would actively mislead callers about
// reachability.
//
// Verification model:
//   * record.signature is checked against record.publisher_pubkey on
//     insert; bad signature → kRejectedSig.
//   * record TTL is checked at insert AND at every get; expired records
//     are silently dropped.
//   * idempotency on (publisher_pubkey, nonce) — re-publishing the same
//     exact record is a no-op so gossip can dedupe.
//
// Threading: ProviderStore is single-threaded today. Wrap externally if
// concurrent callers need it.
// =============================================================================

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace fb::proto { class ProviderRecord; class PrekeyRecord; }

namespace fb::p2p {

// Maximum permitted clock skew when validating records dated in the
// future, in milliseconds. Same threshold as the username log.
constexpr std::uint64_t kRecordClockSkewMs = 5 * 60 * 1000;

// Maximum number of addresses per record. Cap to avoid unbounded gossip
// payloads from misbehaving peers.
constexpr std::size_t kMaxAddressesPerRecord = 16;

// Maximum length of a single address string. "scheme://[ipv6]:port" comes
// in around 60 bytes worst-case; cap at 128 with margin.
constexpr std::size_t kMaxAddressBytes = 128;

// Recommended TTL for self-published records (one hour). Callers can
// pass any value into build_record; this is just the default.
constexpr std::uint64_t kDefaultProviderTtlMs = 60 * 60 * 1000;

// Signing-bytes layout — see provider_records.cpp for full description.
// Pinned canonical form so verifiers don't depend on protobuf
// serialization quirks. The offline_relays vector is appended to the
// canonical bytes after the nonce; an empty vector takes 0 length-
// prefix bytes and is treated as "no relays".
[[nodiscard]] std::vector<std::uint8_t> canonical_signing_bytes(
    std::span<const std::uint8_t> publisher_pubkey,
    const std::vector<std::string>& addresses,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms,
    std::span<const std::uint8_t> nonce,
    const std::vector<std::vector<std::uint8_t>>& offline_relays = {});

// Build + sign a record. Throws std::invalid_argument on bad sizes /
// over-long addresses / empty address list. Each offline_relays entry
// must be 32B (Ed25519 pubkey); empty list = no relays declared.
[[nodiscard]] fb::proto::ProviderRecord build_record(
    std::span<const std::uint8_t> sig_pub,
    std::span<const std::uint8_t> sig_priv,
    const std::vector<std::string>& addresses,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms = kDefaultProviderTtlMs,
    const std::vector<std::vector<std::uint8_t>>& offline_relays = {});

class ProviderStore {
public:
    ProviderStore();
    ~ProviderStore();
    ProviderStore(const ProviderStore&) = delete;
    ProviderStore& operator=(const ProviderStore&) = delete;

    enum class PutResult {
        kAccepted,        // New record stored.
        kAlreadyKnown,    // Same (publisher, nonce) already present, no-op.
        kRejectedSig,     // Signature didn't verify.
        kRejectedFormat,  // Bad sizes / too many addresses / oversize.
        kRejectedExpired, // Already past published_at_ms + ttl_ms.
        kRejectedClock,   // published_at_ms more than skew in the future.
    };

    // Insert or refresh a record. `now_ms` defaults to the system clock
    // when 0; pass an explicit value for deterministic tests.
    PutResult put(const fb::proto::ProviderRecord& record,
                  std::uint64_t now_ms = 0);

    // Fetch every fresh (non-expired) record for a publisher pubkey.
    // Multi-homed peers may have multiple records (one per nonce); the
    // result vector includes all of them.
    [[nodiscard]] std::vector<fb::proto::ProviderRecord> get(
        std::span<const std::uint8_t> publisher_pubkey,
        std::uint64_t now_ms = 0) const;

    // Drop every expired record across every publisher. Returns the
    // number of records pruned.
    std::size_t prune_expired(std::uint64_t now_ms = 0);

    // Number of records currently in the store (across all publishers,
    // expired-or-not — call prune_expired first for a cleaner count).
    [[nodiscard]] std::size_t size() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// =============================================================================
// PrekeyStore — same shape as ProviderStore but for X3DH prekey
// bundles. Lets peers publish their bundles into the DHT and look
// each other's up without a central server (the role the
// `KeyBundleUpload` / `KeyBundleFetch` server-resident frames play
// in the centralized mode).
// =============================================================================

// Canonical signing bytes for a PrekeyRecord.
//
// Two layout versions:
//   * v1 (kPrekeyMagic = "fb.p2p.PrekeyRecord:v1\n") — used when both
//     `pq_pubkey` and `pq_pubkey_sig` are empty. Byte-for-byte identical
//     to the pre-PQ layout; old validators accept records signed this way.
//   * v2 (kPrekeyMagicV2 = "fb.p2p.PrekeyRecord:v2\n") — used when both
//     `pq_pubkey` (1184 B) and `pq_pubkey_sig` (64 B) are non-empty. Same
//     prefix as v1, then appends:
//       uint16_be(pq_pub_len = 1184)  || pq_pubkey
//       uint8(pq_sig_len    = 64)     || pq_pubkey_sig
//     Old validators recompute v1 bytes (they don't know about the PQ
//     fields), the signature mismatches, and the record is rejected —
//     which is the correct behavior for a v2-only consumer.
//
// Throws std::invalid_argument if exactly one PQ field is set, or if any
// size is wrong.
[[nodiscard]] std::vector<std::uint8_t> prekey_canonical_signing_bytes(
    std::span<const std::uint8_t> publisher_pubkey,
    std::span<const std::uint8_t> signed_prekey,
    std::span<const std::uint8_t> signed_prekey_signature,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> pq_pubkey      = {},
    std::span<const std::uint8_t> pq_pubkey_sig  = {});

// Build + sign a prekey record. `sig_pub` is the publisher's identity
// pubkey (Ed25519, 32B). `sig_priv` is the matching 64B secret. The
// caller-supplied `signed_prekey` (32B X25519) is the X3DH SPK; we
// also accept its independent Ed25519 signature `signed_prekey_signature`
// — produced once when the SPK was generated, valid as long as the SPK
// is. (Different from the OUTER record signature, which covers the
// whole record + nonce + ttl.)
//
// Optional PQ fields: when `pq_pubkey` (1184 B ML-KEM-768) and
// `pq_pubkey_sig` (64 B Ed25519 over pq_pubkey by the identity key) are
// supplied, both are embedded in the record and bound into the outer
// signature via the v2 canonical layout. Pass empty spans (default) to
// produce a v1 record that pre-PQ validators still accept.
[[nodiscard]] fb::proto::PrekeyRecord build_prekey_record(
    std::span<const std::uint8_t> sig_pub,
    std::span<const std::uint8_t> sig_priv,
    std::span<const std::uint8_t> signed_prekey,
    std::span<const std::uint8_t> signed_prekey_signature,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms = kDefaultProviderTtlMs,
    std::span<const std::uint8_t> pq_pubkey      = {},
    std::span<const std::uint8_t> pq_pubkey_sig  = {});

class PrekeyStore {
public:
    PrekeyStore();
    ~PrekeyStore();
    PrekeyStore(const PrekeyStore&)            = delete;
    PrekeyStore& operator=(const PrekeyStore&) = delete;

    enum class PutResult {
        kAccepted, kAlreadyKnown, kRejectedSig,
        kRejectedFormat, kRejectedExpired, kRejectedClock,
    };

    PutResult put(const fb::proto::PrekeyRecord& record,
                  std::uint64_t now_ms = 0);

    // Most recent fresh record for a publisher (highest published_at_ms
    // among non-expired entries). Empty if none.
    [[nodiscard]] std::optional<fb::proto::PrekeyRecord> get_latest(
        std::span<const std::uint8_t> publisher_pubkey,
        std::uint64_t now_ms = 0) const;

    // All fresh records for a publisher (multi-publish coexistence).
    [[nodiscard]] std::vector<fb::proto::PrekeyRecord> get_all(
        std::span<const std::uint8_t> publisher_pubkey,
        std::uint64_t now_ms = 0) const;

    std::size_t prune_expired(std::uint64_t now_ms = 0);
    [[nodiscard]] std::size_t size() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::p2p
