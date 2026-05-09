// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// OfflineRelayStore — friend-relay store for offline DMs.
//
// In FinBit's serverless model the central server is no longer
// responsible for queuing DMs to offline recipients. Instead, each
// user designates 1-3 trusted contacts as their "offline relays". When
// alice can't reach bob directly:
//
//   1. Alice sends a PeerEnvelope{kind=OFFLINE_DEPOSIT,
//      recipient_pubkey=bob, payload=encrypted_envelope} to one of
//      bob's relays (a peer the relay trusts as one of bob's friends).
//
//   2. The relay stores (recipient_pubkey, payload) locally — it
//      CAN'T decrypt the payload because the inner Envelope is
//      already AEAD-encrypted to bob.
//
//   3. When bob comes online, he sends OFFLINE_FETCH to each of his
//      relays. Each relay iterates its store and sends back every
//      blob whose recipient_pubkey matches bob, as
//      OFFLINE_DELIVERY messages, then deletes them.
//
//   4. Bob's chat_client routes OFFLINE_DELIVERY through the same
//      Double Ratchet decrypt path as inbound DMs.
//
// Threat model:
//   * Relays see metadata: "alice deposited a blob for bob at time T".
//     They DON'T see message content (AEAD-protected at the
//     application layer above).
//   * A malicious relay can drop deposits silently. Mitigation: use
//     multiple relays; alice deposits to all of them; bob fetches
//     from all and dedups.
//   * A malicious relay can replay deposits to bob. Mitigation:
//     bob's Double Ratchet rejects out-of-order / already-seen
//     ciphertext at the inner layer.
//   * A relay can grow unboundedly if no one ever fetches.
//     Mitigation: per-recipient cap + TTL.
//
// Storage is in-memory by default — relays are expected to be online
// peers; a relay that goes offline drops its queue. Production
// deployments would back this with sqlite_store.
// =============================================================================

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace fb::p2p {

// Per-recipient cap on queued blobs. A peer pretending to be a relay
// for many contacts is bounded in how much it must hold for any one
// of them.
constexpr std::size_t kMaxBlobsPerRecipient = 256;

// Time-to-live on a stored blob. Older blobs are pruned on insert
// or fetch — long-offline recipients risk losing very old DMs, but
// in exchange the relay's memory footprint stays bounded even
// against indefinitely-offline addressees.
constexpr std::uint64_t kDefaultBlobTtlMs = 7ULL * 24 * 60 * 60 * 1000;   // 7 days

class OfflineRelayStore {
public:
    OfflineRelayStore();
    ~OfflineRelayStore();
    OfflineRelayStore(const OfflineRelayStore&)            = delete;
    OfflineRelayStore& operator=(const OfflineRelayStore&) = delete;

    enum class DepositResult {
        kAccepted,        // Stored.
        kRejectedFormat,  // recipient_pubkey wrong size or empty payload.
        kRejectedFull,    // Per-recipient cap exceeded.
    };

    // Drop in a new blob for `recipient_pubkey`. The relay never
    // tries to parse `payload` — it's opaque, encrypted to the
    // recipient at the application layer above.
    DepositResult deposit(std::span<const std::uint8_t> recipient_pubkey,
                            std::span<const std::uint8_t> payload,
                            std::uint64_t now_ms = 0);

    // Fetch and REMOVE every queued blob for `recipient_pubkey`.
    // Returned in deposit order (FIFO). Fresh-only: expired blobs
    // are skipped + pruned at the same time.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>>
    fetch_and_clear(std::span<const std::uint8_t> recipient_pubkey,
                     std::uint64_t now_ms = 0);

    // Drop blobs older than ttl. Returns the number pruned across
    // every recipient.
    std::size_t prune_expired(std::uint64_t now_ms = 0,
                                std::uint64_t ttl_ms = kDefaultBlobTtlMs);

    // Diagnostics.
    [[nodiscard]] std::size_t total_blobs() const;
    [[nodiscard]] std::size_t recipients() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::p2p
