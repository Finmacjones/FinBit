// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// MLS (Messaging Layer Security, RFC 9420) facade — Phase 1 scaffolding.
//
// FinBit channels are MLS groups. The protocol-level MLS state lives in
// Cisco's mlspp library (BSD-3, BoringSSL/OpenSSL backed). This facade hides
// mlspp behind FinBit-shaped types so the rest of the codebase (model/, sync/,
// store/) can call into it without depending on mlspp's headers directly.
//
// PHASE 0 STATUS: stubs throw NotImplemented. The interface is designed so
// the Phase-1 wiring is mechanical:
//   - link mlspp via vcpkg.json (already declared as the `mls` feature)
//   - swap each function body for a thin call into mlspp's group API
//   - persist GroupState blobs through fb::store::SqliteStore::save_session()
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace fb::crypto {

class PendingMlsJoin;

class MlsGroup {
public:
    // Create a brand-new MLS group. `creator_identity` is this user's
    // long-term Ed25519 pubkey; `group_id` is a 32-byte opaque GUID.
    [[nodiscard]] static std::unique_ptr<MlsGroup> create(
        std::span<const std::uint8_t, 32> creator_identity,
        std::span<const std::uint8_t, 32> group_id);

    // Re-hydrate an MLS group from a persisted opaque blob.
    [[nodiscard]] static std::unique_ptr<MlsGroup> from_blob(std::span<const std::uint8_t> blob);

    // Start the join half of the add_member flow. Produces a stateful
    // PendingMlsJoin: the joiner generates a KeyPackage to publish,
    // hands it to the inviter (over a Double Ratchet DM in our wire
    // format), waits for the inviter to broadcast a Welcome, then
    // calls PendingMlsJoin::complete(welcome) to materialize the
    // hydrated MlsGroup. Until complete() runs the joiner has no
    // group state — they're just waiting on a Welcome that may or may
    // not arrive.
    [[nodiscard]] static std::unique_ptr<PendingMlsJoin> start_join(
        std::span<const std::uint8_t, 32> joiner_identity);

    virtual ~MlsGroup() = default;

    // Add a member by KeyPackage bytes — the simple 2-party path.
    // Produces an MLS Welcome (sent to the newcomer) and a Commit
    // that references the embedded Add proposal. The Commit can be
    // applied by the joiner via the Welcome alone, but EXISTING
    // members beyond the inviter cannot apply this Commit because
    // the underlying Proposal was pre-applied to the inviter's
    // local state and the wire Commit only references it. Use the
    // propose_add / handle_proposal / commit_pending triple below
    // for >2-party groups.
    struct AddResult {
        std::vector<std::uint8_t> welcome;
        std::vector<std::uint8_t> commit;
    };
    [[nodiscard]] virtual AddResult add_member(
        std::span<const std::uint8_t> key_package) = 0;

    // Two-broadcast Add for multi-member groups.
    //
    //   propose_add_member(kp)        — returns the wire-form Add
    //     proposal bytes. The inviter broadcasts these to every
    //     existing member (who all call handle_proposal on receipt)
    //     BEFORE calling commit_pending. Each call accumulates one
    //     pending proposal in the local State.
    //
    //   handle_proposal(proposal)     — apply an inbound Proposal
    //     against our local state. Idempotent — receiving the same
    //     proposal twice is a no-op (mlspp dedups internally).
    //
    //   commit_pending()              — close out every staged
    //     proposal (ours + ones we received via handle_proposal)
    //     into a single MLS Commit + Welcome. The commit advances
    //     OUR epoch (self-applied internally), and is broadcast to
    //     every other existing member who then apply_commit's it.
    //     Welcome goes to all newly-added joiners.
    [[nodiscard]] virtual std::vector<std::uint8_t> propose_add_member(
        std::span<const std::uint8_t> key_package) = 0;
    virtual void handle_proposal(std::span<const std::uint8_t> proposal) = 0;
    [[nodiscard]] virtual AddResult commit_pending() = 0;

    // Remove a member by their LeafIndex (returned by add_member or known
    // from the group state).
    [[nodiscard]] virtual std::vector<std::uint8_t> remove_member(std::uint32_t leaf_index) = 0;

    // Encrypt an application message; the returned bytes go inside an
    // Envelope.ciphertext field.
    [[nodiscard]] virtual std::vector<std::uint8_t> application_encrypt(
        std::span<const std::uint8_t> plaintext) = 0;

    // Decrypt an inbound MlsApplicationMessage.
    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>> application_decrypt(
        std::span<const std::uint8_t> mls_msg) = 0;

    // Apply an inbound Commit (e.g. someone else added/removed a member).
    virtual void apply_commit(std::span<const std::uint8_t> commit) = 0;

    // Serialize the current group state for at-rest storage.
    [[nodiscard]] virtual std::vector<std::uint8_t> serialize() const = 0;

    // Number of members currently in the group.
    [[nodiscard]] virtual std::size_t member_count() const = 0;

    // Identity bytes of each current member (BasicCredential's
    // `identity` field; FinBit puts the user's 32-byte Ed25519
    // pubkey there at create / start_join). Used by ChatClient to
    // fan out an MlsCommit to every existing member after add /
    // remove. Order matches mls::Session::roster()'s LeafIndex
    // ordering, but callers shouldn't depend on a specific index.
    [[nodiscard]] virtual std::vector<std::vector<std::uint8_t>>
        member_identities() const = 0;
};

// Pure virtuals; the FB_HAVE_MLS=0 build never constructs an MlsGroup
// (every static factory throws first), so unimplemented overrides
// are unreachable. Keep the interface clean.

// Joiner-side state: holds the freshly-generated mls::Client +
// PendingJoin between key-package publication and Welcome receipt.
// Single-use: complete() consumes the join and returns the hydrated
// MlsGroup. Process-local (not persisted across restarts) — if the
// user restarts before a Welcome arrives, they call start_join again
// and republish a fresh KeyPackage.
class PendingMlsJoin {
public:
    virtual ~PendingMlsJoin() = default;

    // Bytes the joiner must publish to the inviter (typically wrapped
    // in a DmPayload.mls_key_package on FinBit's wire). The same
    // KeyPackage MUST be used for the matching complete() — mlspp
    // pairs the KP's HPKE init key with the Welcome's encryption.
    [[nodiscard]] virtual std::vector<std::uint8_t> key_package() const = 0;

    // Hydrate the MlsGroup from the inviter's Welcome. Throws if the
    // Welcome was generated for a different KeyPackage than ours.
    [[nodiscard]] virtual std::unique_ptr<MlsGroup> complete(
        std::span<const std::uint8_t> welcome) = 0;
};

}  // namespace fb::crypto
