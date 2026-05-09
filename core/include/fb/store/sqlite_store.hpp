// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// SQLite-backed local store for FinBit clients.
//
// Tables:
//   identities    — local user identity (Ed25519 keypair, encrypted at rest
//                   when SQLCipher is wired in; for Phase 0 the secret bytes
//                   are stored in plain SQLite — see TODO below).
//   peer_keys     — known peer public keys + cached fingerprints.
//   prekey_bundles — local-side prekey bundles published to the server.
//   sessions      — opaque ratchet session blobs keyed by peer pubkey.
//   inbox         — received envelopes (ciphertext + decrypted metadata).
//   outbox        — pending outgoing envelopes.
//   carry_ledger  — pairwise bytes-relayed-for / by, used by the Phase 5 P2P
//                   credit system. Schema lives now so the protocol field is
//                   present from day one.
//
// TODO(sqlcipher): swap the underlying SQLite library for SQLCipher and key
// the database with Argon2id-derived bytes from the user's local passphrase.
// Until then, the store is encrypted-in-transit only — anyone with disk
// access reads ratchet sessions in plaintext. The interface here is
// SQLCipher-compatible (open() takes an optional passphrase) so the switch
// is a one-line change in the impl.
// =============================================================================

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fb::store {

class SqliteStore {
public:
    // Open / create the store at `path`.
    //
    // When `master_key` is non-empty (32 bytes — typically derived from
    // the user's vault seed via HKDF), at-rest encryption is enabled:
    // sensitive columns (inbox/outbox plaintext, ratchet sessions,
    // channel state, peer-name cache) are AEAD-wrapped per row using
    // per-table sub-keys derived via HKDF-SHA256(master_key,
    // info="FinBit-DB-<Table>-v1"). Each row carries its own 24-byte
    // random XChaCha20-Poly1305 nonce; AAD binds the row's primary key
    // so a row can't be moved between primary keys.
    //
    // The DB tracks its mode via PRAGMA user_version:
    //   0 = legacy plaintext (no migration triggered)
    //   2 = encrypted (master_key REQUIRED on every open)
    //
    // Opening an encrypted DB without a master_key throws. Opening a
    // legacy-plaintext DB WITH a master_key migrates rows in place
    // inside a single SQLite transaction, then bumps user_version to 2.
    [[nodiscard]] static std::unique_ptr<SqliteStore> open(
        const std::string& path,
        std::span<const std::uint8_t> master_key = {});

    SqliteStore(const SqliteStore&)            = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;
    ~SqliteStore();

    // ---- identities --------------------------------------------------------
    void save_identity(std::span<const std::uint8_t> pub, std::span<const std::uint8_t> sec,
                       const std::string& username);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> load_identity_pub(
        const std::string& username) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> load_identity_sec(
        const std::string& username) const;

    // ---- peer key cache ----------------------------------------------------
    void remember_peer(std::span<const std::uint8_t> peer_pub, const std::string& username);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> lookup_peer(
        const std::string& username) const;

    // ---- ratchet session blobs --------------------------------------------
    void save_session(std::span<const std::uint8_t> peer_pub,
                      std::span<const std::uint8_t> blob);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> load_session(
        std::span<const std::uint8_t> peer_pub) const;

    // ---- messages ----------------------------------------------------------
    void append_inbox(std::span<const std::uint8_t> envelope_id,
                      std::span<const std::uint8_t> peer_pub,
                      std::span<const std::uint8_t> plaintext, std::uint64_t timestamp_ms);
    void append_outbox(std::span<const std::uint8_t> envelope_id,
                       std::span<const std::uint8_t> peer_pub,
                       std::span<const std::uint8_t> ciphertext, std::uint64_t timestamp_ms);

    struct InboxRow {
        std::vector<std::uint8_t> envelope_id;
        std::vector<std::uint8_t> peer_pub;
        std::vector<std::uint8_t> plaintext;
        std::uint64_t timestamp_ms;
    };
    [[nodiscard]] std::vector<InboxRow> recent_inbox(std::size_t limit) const;

    // Outbox row shape mirrors InboxRow on purpose — the column named
    // `ciphertext` actually stores the plaintext bytes that were sent,
    // not the wire-encrypted blob (see append_outbox call sites).
    struct OutboxRow {
        std::vector<std::uint8_t> envelope_id;
        std::vector<std::uint8_t> peer_pub;
        std::vector<std::uint8_t> plaintext;
        std::uint64_t timestamp_ms;
    };
    [[nodiscard]] std::vector<OutboxRow> recent_outbox(std::size_t limit) const;

    // ---- carry-credit ledger (Phase 5; data model lives now) --------------
    void record_carry(std::span<const std::uint8_t> peer_pub, std::int64_t delta_bytes);
    [[nodiscard]] std::int64_t carry_balance(std::span<const std::uint8_t> peer_pub) const;

    // ---- server-side persistent offline queue (Phase 1) ------------------
    // Blob is the serialized Envelope. Recipient is the user pubkey the
    // envelope is addressed to.
    void srv_offline_enqueue(std::span<const std::uint8_t> recipient_pub,
                             std::span<const std::uint8_t> envelope_bytes,
                             std::uint64_t timestamp_ms);
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> srv_offline_drain(
        std::span<const std::uint8_t> recipient_pub);

    // ---- server-side persistent directory (Phase 1.5) --------------------
    // username -> identity pubkey (last writer wins; same semantics as the
    // in-memory Directory). Bundles are stored separately keyed by pubkey.
    void srv_register_user(const std::string& username,
                           std::span<const std::uint8_t> pubkey);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> srv_resolve_username(
        const std::string& username) const;
    [[nodiscard]] std::optional<std::string> srv_reverse_resolve_pubkey(
        std::span<const std::uint8_t> pubkey) const;
    void srv_put_prekey_bundle(std::span<const std::uint8_t> owner_pub,
                               std::span<const std::uint8_t> bundle_blob);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> srv_get_prekey_bundle(
        std::span<const std::uint8_t> owner_pub) const;

    // ---- client-side channel persistence (Phase 1.5) ---------------------
    // Per-channel cipher discriminator. Old channels created before MLS
    // landed have no `crypto` column on disk → read back as kSenderKeys
    // (= 0). New channels can be created with kMls; the inbound channel
    // envelope path branches on this value to pick the right decoder.
    enum class ChannelCrypto : int {
        kSenderKeys = 0,
        kMls        = 1,
    };

    // A "channel" row holds the user-facing name and 32-byte channel id, plus
    // our own SenderKeysDistribution blob (the chain we use for sending) and
    // the per-channel cipher discriminator.
    void chan_save(const std::string& name, std::span<const std::uint8_t> channel_id,
                   std::span<const std::uint8_t> own_dist,
                   ChannelCrypto crypto = ChannelCrypto::kSenderKeys);
    struct ChannelRow {
        std::string               name;
        std::vector<std::uint8_t> channel_id;
        std::vector<std::uint8_t> own_dist;
        ChannelCrypto             crypto = ChannelCrypto::kSenderKeys;
    };
    [[nodiscard]] std::vector<ChannelRow> chan_list() const;

    // chan_peers stores installed peer distributions per (channel_id, peer_pub).
    void chan_save_peer(std::span<const std::uint8_t> channel_id,
                        std::span<const std::uint8_t> peer_pub,
                        std::span<const std::uint8_t> peer_dist);
    struct ChannelPeerRow {
        std::vector<std::uint8_t> peer_pub;
        std::vector<std::uint8_t> peer_dist;
    };
    [[nodiscard]] std::vector<ChannelPeerRow> chan_peers(
        std::span<const std::uint8_t> channel_id) const;

    // chan_inbox: persisted decrypted channel messages.
    void chan_append_inbox(std::span<const std::uint8_t> channel_id,
                           std::span<const std::uint8_t> sender_pub,
                           std::span<const std::uint8_t> plaintext,
                           std::uint64_t timestamp_ms);
    struct ChannelInboxRow {
        std::vector<std::uint8_t> channel_id;
        std::vector<std::uint8_t> sender_pub;
        std::vector<std::uint8_t> plaintext;
        std::uint64_t             timestamp_ms;
    };
    [[nodiscard]] std::vector<ChannelInboxRow> chan_recent_inbox(
        std::span<const std::uint8_t> channel_id, std::size_t limit) const;

    // Forget a channel entirely: chan_state row, chan_peers, chan_inbox,
    // mls_group_state + mls_group_log if any. Caller is responsible
    // for any associated session-blob row in `sessions` (chan_state
    // stores name, but the GroupSession blob lives under
    // sessions/__chanstate__:<name>).
    void chan_delete(const std::string& name,
                     std::span<const std::uint8_t> channel_id);

    // ---- MLS persistence (operation-replay model) --------------------
    //
    // Two paired tables. mls_group_save writes (or replaces) the
    // bootstrap seed for a kMls channel — call this exactly once at
    // group creation or Welcome-completion. Then for every state-
    // mutating effect MlsGroup applied (proposals, commits, applies),
    // call mls_group_op_append with the next sequence number; the
    // store enforces uniqueness so duplicate appends on retry won't
    // corrupt the log. mls_group_load returns the seed + the full
    // ordered op list, suitable for handing to
    // MlsGroup::from_seed_and_log.
    //
    // Both tables AEAD-wrap the secret material at rest (per-table
    // HKDF subkey, AAD = channel_id for state, channel_id||be64(seq)
    // for log entries).
    void mls_group_save(std::span<const std::uint8_t> channel_id,
                        std::span<const std::uint8_t> seed_blob);
    void mls_group_op_append(std::span<const std::uint8_t> channel_id,
                             std::int64_t seq,
                             std::span<const std::uint8_t> op_blob);
    struct MlsGroupSnapshot {
        std::vector<std::uint8_t>              seed;
        std::vector<std::vector<std::uint8_t>> ops;
        std::int64_t                           next_seq = 0;
    };
    [[nodiscard]] std::optional<MlsGroupSnapshot> mls_group_load(
        std::span<const std::uint8_t> channel_id) const;
    void mls_group_delete(std::span<const std::uint8_t> channel_id);

    // peer_cache: username <-> pubkey we've learned (e.g. as DM peers).
    void cache_peer_name(std::span<const std::uint8_t> peer_pub, const std::string& username);
    [[nodiscard]] std::optional<std::string> peer_name(
        std::span<const std::uint8_t> peer_pub) const;
    struct CachedPeer {
        std::vector<std::uint8_t> peer_pub;
        std::string               username;
    };
    [[nodiscard]] std::vector<CachedPeer> all_cached_peers() const;

private:
    SqliteStore();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fb::store
