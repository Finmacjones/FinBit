// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// SenderKeys — pre-MLS group encryption.
//
// Each group member maintains a per-(group, sender) symmetric chain key. To
// send: derive a fresh message key from the chain, AEAD-encrypt, then ratchet
// the chain forward. To receive: locate the matching (sender, message-index)
// chain step, derive the same message key, AEAD-decrypt.
//
// Properties (compared to the Double Ratchet):
//   + Trivially scales to N members — each receiver maintains O(N) chains, not
//     O(N^2). One application-level encrypt = one AEAD op.
//   + Forward secrecy: a message key is never reused; the chain ratchets after
//     every send.
//   - No backward secrecy on its own (a leaked chain key compromises all
//     future messages from that sender). Mitigation: the sender periodically
//     re-issues a fresh chain (DistributionMessage), securely delivered to
//     each member via their pairwise Double Ratchet session.
//   - No automatic post-removal exclusion: when a member is removed the
//     remaining members must re-issue a fresh chain so the leaver's stored
//     chain key is useless going forward.
//
// This is the design Signal used for groups before MLS. Real MLS via mlspp
// is the long-term plan (see crypto/mls_facade.hpp); SenderKeys is what
// FinBit uses today so Phase 1 group chats actually work without a
// 100k-LOC dependency.
//
// Wire formats live in proto/sender_keys.proto.
// =============================================================================

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace fb::crypto {

class SenderChain {
public:
    // Construct a chain from a fresh 32-byte chain seed.
    explicit SenderChain(std::span<const std::uint8_t, 32> seed);

    // Encrypt the next message. Returns serialized SenderKeysMessage bytes.
    [[nodiscard]] std::vector<std::uint8_t> encrypt(std::span<const std::uint8_t> plaintext,
                                                    std::span<const std::uint8_t> aad);

    [[nodiscard]] std::uint32_t next_index() const noexcept { return next_index_; }
    [[nodiscard]] std::array<std::uint8_t, 32> current_key() const noexcept { return chain_key_; }

private:
    std::array<std::uint8_t, 32> chain_key_;
    std::uint32_t next_index_ = 0;
};

// Per-group session held by every member. Sender side uses a SenderChain;
// receiver side keeps a per-sender chain key + cached message keys for skips.
class GroupSession {
public:
    static constexpr std::size_t kMaxSkip = 1000;

    GroupSession();
    GroupSession(const GroupSession&)            = delete;
    GroupSession& operator=(const GroupSession&) = delete;
    GroupSession(GroupSession&&) noexcept;
    GroupSession& operator=(GroupSession&&) noexcept;
    ~GroupSession();

    // ---- sender side -------------------------------------------------------

    // Initialize our own send chain with a freshly-generated seed. Returns the
    // distribution payload to send to each peer (over their pairwise Double
    // Ratchet session) so they can decrypt our future messages.
    [[nodiscard]] std::vector<std::uint8_t> create_own_send_chain();

    // Encrypt a group message. Returns serialized SenderKeysMessage.
    [[nodiscard]] std::vector<std::uint8_t> encrypt(std::span<const std::uint8_t> plaintext,
                                                    std::span<const std::uint8_t> aad);

    // ---- receiver side -----------------------------------------------------

    // Install or replace a peer's distribution. `peer_id` is an opaque tag
    // (e.g. their identity pubkey). Subsequent SenderKeysMessages from this
    // peer can be decrypted.
    void install_peer_distribution(std::span<const std::uint8_t> peer_id,
                                   std::span<const std::uint8_t> distribution);

    // Decrypt a SenderKeysMessage from `peer_id`. Returns nullopt if the
    // peer is unknown or the message is malformed / tampered / too-far-skipped
    // / replayed.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt(
        std::span<const std::uint8_t> peer_id,
        std::span<const std::uint8_t> sender_keys_msg,
        std::span<const std::uint8_t> aad);

    // Eject a member. Drops the chain so post-eviction messages from them
    // cannot be decrypted (defense in depth — they should also stop sending).
    void remove_peer(std::span<const std::uint8_t> peer_id);

    // Diagnostic: number of distinct peers we can decrypt from.
    [[nodiscard]] std::size_t peer_count() const noexcept;

    // Serialize the full session state (own chain + per-peer chains, excluding
    // the in-memory skipped-key cache) so a client can persist channel state
    // across restarts. Wire format is FinBit-internal binary, not protobuf —
    // never sent over the wire.
    [[nodiscard]] std::vector<std::uint8_t> serialize_state() const;

    // Restore a previously serialized session. Returns nullptr on malformed
    // input. Skipped-key cache starts empty.
    [[nodiscard]] static std::unique_ptr<GroupSession> deserialize_state(
        std::span<const std::uint8_t> blob);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Free helpers exposed for testing / fb-cli.
[[nodiscard]] std::array<std::uint8_t, 32> derive_message_key(
    std::span<const std::uint8_t, 32> chain_key);
[[nodiscard]] std::array<std::uint8_t, 32> ratchet_chain_key(
    std::span<const std::uint8_t, 32> chain_key);

}  // namespace fb::crypto
