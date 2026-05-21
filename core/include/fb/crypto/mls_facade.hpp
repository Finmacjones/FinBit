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

#include <array>
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

    // ---- Persistence (operation-log replay model) --------------------
    //
    // mlspp does not expose mls::State (de)serialization on its public
    // API, and `state.handle(my_own_commit)` refuses to apply commits
    // we authored ourselves (it requires a cached_state, which is
    // exactly what we're trying to reconstruct). Wire-commit replay
    // is therefore not viable.
    //
    // Instead the facade saves the seed plus an OPERATION LOG: an
    // ordered list of effects we applied (proposals staged, commits
    // produced or applied), each capturing the inputs we used —
    // including any random leaf_secret consumed inside state.commit.
    // On restore the seed rebuilds the empty State, then each op is
    // RE-EXECUTED in order. Re-execution produces an identical State
    // because every input is preserved; the resulting State at the
    // end of the log is byte-equivalent to the live one.
    //
    // Two storage primitives:
    //
    //   serialize_seed() — small, written ONCE at group creation /
    //     join completion. Holds the cipher suite, group id, our
    //     credential identity, the private keys we generated
    //     (sig_priv, leaf_priv, plus init_priv + KeyPackage +
    //     Welcome for joiners), the random init_secret used at
    //     epoch 0 (creator only), and a marshaled LeafNode (creator
    //     only). 500–1500 bytes typical. Treat as secret — callers
    //     MUST AEAD-wrap before writing to disk.
    //
    //   operation_log() — every effect we applied since seeding, in
    //     apply order. Each entry is an opaque blob the caller stores
    //     in an append-only table; on restore, hand the full ordered
    //     vector to from_seed_and_log. Most entries are 100–500 bytes;
    //     larger ones (Welcomes, KeyPackages) up to a few KB. The
    //     transcript stays bounded in normal use (one entry per
    //     proposal/commit/apply event).
    //
    // serialize() bundles seed + log into a single blob (useful for
    // backup/export/test). For the hot path prefer the split form
    // so individual ops can be appended incrementally instead of
    // re-serialising the entire log.
    [[nodiscard]] virtual std::vector<std::uint8_t> serialize_seed() const = 0;
    [[nodiscard]] virtual std::vector<std::vector<std::uint8_t>>
        operation_log() const = 0;
    [[nodiscard]] virtual std::vector<std::uint8_t> serialize() const = 0;

    // Restore from the split form. seed must be exactly the bytes
    // returned by serialize_seed(); ops must be the full ordered
    // list returned by operation_log() at the corresponding moment.
    // Throws on malformed seed, key-parse failure, or any op that
    // fails to re-execute against the rebuilt state.
    [[nodiscard]] static std::unique_ptr<MlsGroup> from_seed_and_log(
        std::span<const std::uint8_t> seed,
        const std::vector<std::vector<std::uint8_t>>& ops);

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

    // ---- Group-call keying (RFC 9420 §8.5 exporter) ------------------
    //
    // The current MLS epoch. Bumps on every Commit (add/remove/update),
    // so it doubles as the group call's SFrame rotation epoch — when
    // membership changes, the room re-keys automatically.
    [[nodiscard]] virtual std::uint64_t epoch() const = 0;

    // Derive the per-room SFrame base secret for a group call in THIS
    // channel, straight from the MLS exporter. Every member at the same
    // epoch derives the identical 32 bytes with no extra message and no
    // distribution DM (unlike the SenderKeys path, which ships a RoomKey
    // over the ratchet) — and it rotates for free on every Commit because
    // the exporter secret does. Feed the result to
    // `fb::media::derive_room_sframe_key(secret, sender_pubkey, epoch())`
    // to get each sender's call key; the forwarder stays blind.
    [[nodiscard]] virtual std::array<std::uint8_t, 32>
        export_room_secret() const = 0;
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
