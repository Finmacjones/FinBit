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

class MlsGroup {
public:
    // Create a brand-new MLS group. `creator_identity` is this user's
    // long-term Ed25519 pubkey; `group_id` is a 32-byte opaque GUID.
    [[nodiscard]] static std::unique_ptr<MlsGroup> create(
        std::span<const std::uint8_t, 32> creator_identity,
        std::span<const std::uint8_t, 32> group_id);

    // Re-hydrate an MLS group from a persisted opaque blob.
    [[nodiscard]] static std::unique_ptr<MlsGroup> from_blob(std::span<const std::uint8_t> blob);

    virtual ~MlsGroup() = default;

    // Add a member by KeyPackage bytes. Produces an MLS Welcome (sent to the
    // newcomer) and a Commit (broadcast to existing members).
    struct AddResult {
        std::vector<std::uint8_t> welcome;
        std::vector<std::uint8_t> commit;
    };
    [[nodiscard]] virtual AddResult add_member(
        std::span<const std::uint8_t> key_package) = 0;

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
};

}  // namespace fb::crypto
