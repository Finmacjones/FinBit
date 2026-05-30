// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/store/sqlite_store.hpp"

#include <sodium.h>
#include <sqlite3.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <string>
#include <utility>

#include "fb/crypto/hkdf.hpp"

namespace fb::store {
namespace {

constexpr const char* kSchema = R"sql(
CREATE TABLE IF NOT EXISTS identities (
    username TEXT PRIMARY KEY,
    pub      BLOB NOT NULL,
    sec      BLOB NOT NULL  -- TODO(sqlcipher): db-level encryption
);
CREATE TABLE IF NOT EXISTS peer_keys (
    username TEXT PRIMARY KEY,
    pub      BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS prekey_bundles (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_blob  BLOB NOT NULL,
    consumed     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    peer_pub  BLOB PRIMARY KEY,
    blob      BLOB NOT NULL,
    updated_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS inbox (
    envelope_id BLOB PRIMARY KEY,
    peer_pub    BLOB NOT NULL,
    plaintext   BLOB NOT NULL,
    ts_ms       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inbox_ts ON inbox(ts_ms DESC);
CREATE TABLE IF NOT EXISTS outbox (
    envelope_id BLOB PRIMARY KEY,
    peer_pub    BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    ts_ms       INTEGER NOT NULL,
    sent        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS carry_ledger (
    peer_pub      BLOB PRIMARY KEY,
    delta_bytes   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS srv_offline (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_pub BLOB NOT NULL,
    envelope      BLOB NOT NULL,
    ts_ms         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_srv_offline_rcpt ON srv_offline(recipient_pub, id);
CREATE TABLE IF NOT EXISTS srv_directory (
    username  TEXT PRIMARY KEY,
    pubkey    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS srv_prekey_bundles (
    owner_pub BLOB PRIMARY KEY,
    bundle    BLOB NOT NULL,
    updated_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chan_state (
    name       TEXT PRIMARY KEY,
    channel_id BLOB NOT NULL,
    own_dist   BLOB,
    -- Per-channel cipher discriminator. 0 = SenderKeys (legacy/default),
    -- 1 = MLS (RFC 9420 via mlspp). Old DBs without this column read back
    -- as 0 thanks to ALTER TABLE ... DEFAULT 0 below — added in a
    -- migration pass that's idempotent (CREATE IF NOT EXISTS makes the
    -- ALTER necessary on upgrades).
    crypto     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chan_peers (
    channel_id BLOB NOT NULL,
    peer_pub   BLOB NOT NULL,
    peer_dist  BLOB NOT NULL,
    PRIMARY KEY(channel_id, peer_pub)
);
CREATE TABLE IF NOT EXISTS chan_inbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id  BLOB NOT NULL,
    sender_pub  BLOB NOT NULL,
    plaintext   BLOB NOT NULL,
    ts_ms       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chan_inbox_chan ON chan_inbox(channel_id, ts_ms DESC);
CREATE TABLE IF NOT EXISTS peer_name_cache (
    peer_pub  BLOB PRIMARY KEY,
    username  TEXT NOT NULL,
    learned_ms INTEGER NOT NULL DEFAULT 0
);
-- MLS persistence (operation-replay model). One row per kMls channel
-- in mls_group_state holding the bootstrap seed (creator: identity +
-- sig_priv + leaf_priv + epoch-0 init_secret + LeafNode bytes;
-- joiner: identity + sig_priv + init_priv + leaf_priv + KeyPackage +
-- Welcome). Append-only mls_group_log captures each state-mutating
-- effect (proposals staged, commits produced/applied) — on restart
-- we hand seed + ordered ops to MlsGroup::from_seed_and_log to
-- rebuild State.
--
-- Both tables are AEAD-wrapped at-rest with separate per-table HKDF
-- subkeys. AAD = channel_id (state) or channel_id||be64(seq) (log)
-- so a row can't be silently moved or reordered.
CREATE TABLE IF NOT EXISTS mls_group_state (
    channel_id    BLOB PRIMARY KEY,
    seed_blob     BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mls_group_log (
    channel_id    BLOB NOT NULL,
    seq           INTEGER NOT NULL,
    op_blob       BLOB NOT NULL,
    applied_at_ms INTEGER NOT NULL,
    PRIMARY KEY (channel_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_mls_group_log_chan
    ON mls_group_log(channel_id, seq);
-- Tier-11 forward-secret local storage Phase 2: persisted per-table
-- sub-keys for storage_keys-driven key rotation. Each row holds an
-- AEAD-wrapped sub-key (wrapped under the vault master key with AAD =
-- name || generation_be). On rotate_storage_keys(): generate new sub-
-- keys, re-wrap all rows in the affected tables under them, write the
-- new wrapped sub-keys here with generation+1, sodium_memzero the old
-- in-memory sub-keys. A memory dump captured BEFORE the rotation has
-- only the OLD sub-keys → can decrypt nothing on the post-rotation
-- disk state. Doesn't help against passphrase compromise (Phase 1's
-- TTL handles that).
CREATE TABLE IF NOT EXISTS storage_keys (
    name       TEXT    PRIMARY KEY,
    wrapped    BLOB    NOT NULL,
    generation INTEGER NOT NULL
);
-- Tier-11 MITM verification: "human verified this peer's identity"
-- bit. Set true when the user has compared the safety number with the
-- peer out-of-band; clears (or stays false) otherwise. The UI uses it
-- to render a ✓ badge AND to warn-on-pubkey-change when an already-
-- verified peer's pubkey changes (typically: someone reinstalled,
-- maybe not — re-verify in person).
CREATE TABLE IF NOT EXISTS peer_verified (
    peer_pub       BLOB    PRIMARY KEY,
    verified       INTEGER NOT NULL DEFAULT 0,
    verified_at_ms INTEGER NOT NULL DEFAULT 0
);
-- Tier-11 Shamir social recovery: trustee-side share custody. Each row
-- is a Shamir share that some peer entrusted to this user. Identified
-- by (peer_pub, setup_id) so a single peer can have multiple parallel
-- setups. On a future ShamirShareRequest from that peer (or any user
-- the trustee authenticates out-of-band), the UI looks the share up
-- and the user approves sending it back.
CREATE TABLE IF NOT EXISTS shamir_held_shares (
    peer_pub       BLOB    NOT NULL,
    setup_id       INTEGER NOT NULL,
    share          BLOB    NOT NULL,
    threshold      INTEGER NOT NULL,
    total          INTEGER NOT NULL,
    label          TEXT    NOT NULL DEFAULT '',
    received_at_ms INTEGER NOT NULL,
    PRIMARY KEY (peer_pub, setup_id)
);
)sql";

void throw_sqlite(const std::string& ctx, sqlite3* db) {
    throw std::runtime_error(ctx + ": " + (db ? sqlite3_errmsg(db) : "no db"));
}

// XChaCha20-Poly1305-IETF parameters.
constexpr std::size_t kXNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;   // 24
constexpr std::size_t kXTag   = crypto_aead_xchacha20poly1305_ietf_ABYTES;      // 16
constexpr std::size_t kKeyLen = 32;

// HKDF-SHA256 expand-only with no salt (master_key acts as the
// pseudo-random key already; we just label the output per table).
std::array<std::uint8_t, kKeyLen> derive_table_key(
    std::span<const std::uint8_t> master_key, const char* info) {
    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(master_key.data(), master_key.size()));
    auto vec = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(info),
            std::strlen(info)),
        kKeyLen);
    std::array<std::uint8_t, kKeyLen> out{};
    std::memcpy(out.data(), vec.data(), kKeyLen);
    return out;
}

// Wrap `plaintext` as `nonce(24) || ct+tag`. AAD binds `aad` (typically
// the row's primary-key bytes) so a row can't be quietly relocated.
std::vector<std::uint8_t> aead_wrap(
    const std::array<std::uint8_t, kKeyLen>& key,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> aad) {
    std::vector<std::uint8_t> out(kXNonce + plaintext.size() + kXTag);
    std::uint8_t* nonce = out.data();
    std::uint8_t* ct    = nonce + kXNonce;
    randombytes_buf(nonce, kXNonce);
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len, plaintext.data(), plaintext.size(),
            aad.data(), aad.size(), nullptr, nonce, key.data()) != 0) {
        throw std::runtime_error("aead_wrap: encrypt failed");
    }
    out.resize(kXNonce + ct_len);
    return out;
}

// Inverse of aead_wrap. Returns nullopt on tag-mismatch (corruption,
// wrong key, or row-relocation attack — the AAD-as-PK binding makes
// the last case detectable).
std::optional<std::vector<std::uint8_t>> aead_unwrap(
    const std::array<std::uint8_t, kKeyLen>& key,
    std::span<const std::uint8_t> blob,
    std::span<const std::uint8_t> aad) {
    if (blob.size() < kXNonce + kXTag) return std::nullopt;
    const std::uint8_t* nonce = blob.data();
    const std::uint8_t* ct    = nonce + kXNonce;
    const std::size_t   ct_len = blob.size() - kXNonce;
    std::vector<std::uint8_t> out(ct_len - kXTag);
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.data(), &pt_len, nullptr, ct, ct_len,
            aad.data(), aad.size(), nonce, key.data()) != 0) {
        return std::nullopt;
    }
    out.resize(pt_len);
    return out;
}

}  // namespace

struct SqliteStore::Impl {
    sqlite3* db = nullptr;

    // At-rest encryption state. encrypt_at_rest is true exactly when
    // open() received a non-empty master_key. inbox_key / outbox_key
    // are derived once at open via HKDF; nullptr keys when disabled.
    bool encrypt_at_rest = false;
    std::array<std::uint8_t, kKeyLen> inbox_key{};
    std::array<std::uint8_t, kKeyLen> outbox_key{};
    std::array<std::uint8_t, kKeyLen> sessions_key{};
    std::array<std::uint8_t, kKeyLen> chan_state_key{};
    std::array<std::uint8_t, kKeyLen> chan_peers_key{};
    std::array<std::uint8_t, kKeyLen> chan_inbox_key{};
    std::array<std::uint8_t, kKeyLen> peer_name_key{};
    std::array<std::uint8_t, kKeyLen> mls_state_key{};
    std::array<std::uint8_t, kKeyLen> mls_log_key{};

    // Tier-11 Phase 2 — kept around so rotate_storage_keys() can re-wrap
    // freshly-generated sub-keys under it. zeroize on destruction.
    std::array<std::uint8_t, kKeyLen> master_key{};
    bool                              have_master = false;
    // Rotation generation counter (incremented on each successful
    // rotate_storage_keys call; bound into the AAD of the wrapped
    // sub-keys so a row swap across generations fails AEAD verify).
    std::uint64_t                     storage_keys_generation = 0;

    ~Impl() {
        // Best-effort: zero the table keys before the process exits so
        // a core-dump after Close-without-Quit doesn't carry them.
        sodium_memzero(master_key.data(),      master_key.size());
        sodium_memzero(inbox_key.data(),       inbox_key.size());
        sodium_memzero(outbox_key.data(),      outbox_key.size());
        sodium_memzero(sessions_key.data(),    sessions_key.size());
        sodium_memzero(chan_state_key.data(),  chan_state_key.size());
        sodium_memzero(chan_peers_key.data(),  chan_peers_key.size());
        sodium_memzero(chan_inbox_key.data(),  chan_inbox_key.size());
        sodium_memzero(peer_name_key.data(),   peer_name_key.size());
        sodium_memzero(mls_state_key.data(),   mls_state_key.size());
        sodium_memzero(mls_log_key.data(),     mls_log_key.size());
        if (db) sqlite3_close(db);
    }

    void exec(const std::string& sql) {
        char* err = nullptr;
        if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
            const std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            throw std::runtime_error("sqlite_exec: " + msg);
        }
    }

    sqlite3_stmt* prep(const char* sql) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw_sqlite("prepare", db);
        }
        return stmt;
    }
};

SqliteStore::SqliteStore() : impl_(std::make_unique<Impl>()) {}
SqliteStore::~SqliteStore() = default;

namespace {
// v0 = legacy plaintext schema (no migration). v2 = inbox + outbox
// encrypted (interim release). v3 = also sessions, channel state,
// channel peers, channel inbox, peer-name cache. New encrypted DBs
// are created at v3 directly.
constexpr int kSchemaVersionEncrypted = 3;

int read_user_version(sqlite3* db) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    int v = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        v = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return v;
}
}  // namespace

std::unique_ptr<SqliteStore> SqliteStore::open(
    const std::string& path,
    std::span<const std::uint8_t> master_key) {
    auto s = std::unique_ptr<SqliteStore>(new SqliteStore());
    if (sqlite3_open(path.c_str(), &s->impl_->db) != SQLITE_OK) {
        throw_sqlite("open", s->impl_->db);
    }
    s->impl_->exec(kSchema);
    // Idempotent column adds for legacy DBs created before each MLS-
    // related column shipped. SQLite's CREATE TABLE IF NOT EXISTS
    // can't extend an existing table; ALTER TABLE ADD COLUMN is the
    // standard pattern. Each ALTER is wrapped in a try/swallow because
    // SQLite returns SQLITE_ERROR (and our exec() throws) when the
    // column already exists, and we want the call to be safely
    // re-runnable on every open.
    auto try_add_column = [&](const char* sql) {
        try { s->impl_->exec(sql); } catch (const std::exception&) {}
    };
    try_add_column(
        "ALTER TABLE chan_state ADD COLUMN crypto INTEGER NOT NULL DEFAULT 0;");
    // Tier-11 forward-secret local storage: per-row expiry. Legacy rows
    // default to 0 (never expire), so existing DBs are unaffected until
    // a sender starts setting DmPayload.ttl_ms.
    try_add_column(
        "ALTER TABLE inbox  ADD COLUMN expires_at_ms INTEGER NOT NULL DEFAULT 0;");
    try_add_column(
        "ALTER TABLE outbox ADD COLUMN expires_at_ms INTEGER NOT NULL DEFAULT 0;");
    s->impl_->exec("PRAGMA journal_mode = WAL;");
    s->impl_->exec("PRAGMA synchronous = NORMAL;");

    const int version = read_user_version(s->impl_->db);
    const bool have_key = !master_key.empty();
    if (have_key && master_key.size() != kKeyLen) {
        throw std::runtime_error(
            "SqliteStore::open: master_key must be exactly 32 bytes");
    }

    if (version == kSchemaVersionEncrypted && !have_key) {
        throw std::runtime_error(
            "SqliteStore::open: database is encrypted at rest "
            "(user_version=2) but no master_key was provided");
    }
    if (have_key) {
        s->impl_->encrypt_at_rest = true;
        std::memcpy(s->impl_->master_key.data(), master_key.data(), kKeyLen);
        s->impl_->have_master = true;
        s->impl_->inbox_key       = derive_table_key(master_key, "FinBit-DB-Inbox-v1");
        s->impl_->outbox_key      = derive_table_key(master_key, "FinBit-DB-Outbox-v1");
        s->impl_->sessions_key    = derive_table_key(master_key, "FinBit-DB-Sessions-v1");
        s->impl_->chan_state_key  = derive_table_key(master_key, "FinBit-DB-ChanState-v1");
        s->impl_->chan_peers_key  = derive_table_key(master_key, "FinBit-DB-ChanPeers-v1");
        s->impl_->chan_inbox_key  = derive_table_key(master_key, "FinBit-DB-ChanInbox-v1");
        s->impl_->peer_name_key   = derive_table_key(master_key, "FinBit-DB-PeerName-v1");
        s->impl_->mls_state_key   = derive_table_key(master_key, "FinBit-DB-MlsState-v1");
        s->impl_->mls_log_key     = derive_table_key(master_key, "FinBit-DB-MlsLog-v1");

        // Tier-11 Phase 2: if a prior rotation has persisted sub-keys
        // for any of {inbox, outbox, sessions}, override the
        // deterministic derivation with the unwrapped persisted value.
        // Tables not yet covered by rotation keep the deterministic
        // sub-key (backward compatible).
        auto load_wrapped = [&](const char* name) -> std::optional<std::array<std::uint8_t, kKeyLen>> {
            auto* stmt = s->impl_->prep(
                "SELECT wrapped, generation FROM storage_keys WHERE name = ?;");
            sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
            std::optional<std::array<std::uint8_t, kKeyLen>> out;
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const auto blob_len = sqlite3_column_bytes(stmt, 0);
                const auto* blob_ptr =
                    static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt, 0));
                const std::uint64_t gen = static_cast<std::uint64_t>(
                    sqlite3_column_int64(stmt, 1));
                // AAD = name || generation_be — binds the row to its slot
                // + generation, so an attacker can't swap one row's
                // wrapped key into another's.
                std::vector<std::uint8_t> aad;
                aad.insert(aad.end(),
                            reinterpret_cast<const std::uint8_t*>(name),
                            reinterpret_cast<const std::uint8_t*>(name) +
                                std::strlen(name));
                for (int i = 7; i >= 0; --i) {
                    aad.push_back(static_cast<std::uint8_t>((gen >> (8 * i)) & 0xff));
                }
                auto unwrapped = aead_unwrap(
                    s->impl_->master_key,
                    std::span<const std::uint8_t>(blob_ptr, static_cast<std::size_t>(blob_len)),
                    std::span<const std::uint8_t>(aad.data(), aad.size()));
                if (unwrapped && unwrapped->size() == kKeyLen) {
                    std::array<std::uint8_t, kKeyLen> k{};
                    std::memcpy(k.data(), unwrapped->data(), kKeyLen);
                    out = k;
                    if (gen > s->impl_->storage_keys_generation) {
                        s->impl_->storage_keys_generation = gen;
                    }
                }
            }
            sqlite3_finalize(stmt);
            return out;
        };
        if (auto k = load_wrapped("inbox"))    s->impl_->inbox_key    = *k;
        if (auto k = load_wrapped("outbox"))   s->impl_->outbox_key   = *k;
        if (auto k = load_wrapped("sessions")) s->impl_->sessions_key = *k;
    }
    if (have_key && version < kSchemaVersionEncrypted) {
        // Migration from legacy plaintext (v0) or partially-encrypted
        // (v2 — inbox+outbox only). Single transaction across every
        // table so a crash mid-migration leaves the DB readable either
        // fully wrapped or fully plaintext, never partial.
        s->impl_->exec("BEGIN IMMEDIATE;");
        try {
            // Common inner step: read every (aad, plaintext) row from a
            // table, wrap each plaintext under `key` with the row's aad,
            // and UPDATE the column. select_sql / update_sql arrays are
            // SQLite text; aad_cols + plaintext_col are 0-based column
            // indices on the SELECT result.
            auto wrap_table = [&](const auto& key,
                                  const char* select_sql,
                                  const char* update_sql,
                                  std::initializer_list<int> aad_cols,
                                  int plaintext_col) {
                struct Row {
                    std::vector<std::uint8_t> aad;
                    std::vector<std::uint8_t> pt;
                    std::vector<std::vector<std::uint8_t>> where_keys;
                };
                std::vector<Row> rows;
                sqlite3_stmt* sel = s->impl_->prep(select_sql);
                while (sqlite3_step(sel) == SQLITE_ROW) {
                    Row r;
                    for (int col : aad_cols) {
                        const auto* p = static_cast<const std::uint8_t*>(
                            sqlite3_column_blob(sel, col));
                        const int n = sqlite3_column_bytes(sel, col);
                        r.where_keys.emplace_back(p, p + n);
                        r.aad.insert(r.aad.end(), p, p + n);
                    }
                    const auto* p = static_cast<const std::uint8_t*>(
                        sqlite3_column_blob(sel, plaintext_col));
                    const int n = sqlite3_column_bytes(sel, plaintext_col);
                    r.pt.assign(p, p + n);
                    rows.push_back(std::move(r));
                }
                sqlite3_finalize(sel);
                sqlite3_stmt* upd = s->impl_->prep(update_sql);
                for (const auto& r : rows) {
                    auto wrapped = aead_wrap(key,
                        std::span<const std::uint8_t>(r.pt.data(), r.pt.size()),
                        std::span<const std::uint8_t>(r.aad.data(), r.aad.size()));
                    int idx = 1;
                    sqlite3_bind_blob(upd, idx++, wrapped.data(),
                                      static_cast<int>(wrapped.size()),
                                      SQLITE_TRANSIENT);
                    for (const auto& k : r.where_keys) {
                        sqlite3_bind_blob(upd, idx++, k.data(),
                                          static_cast<int>(k.size()),
                                          SQLITE_TRANSIENT);
                    }
                    if (sqlite3_step(upd) != SQLITE_DONE) {
                        sqlite3_finalize(upd);
                        throw std::runtime_error("migration UPDATE failed");
                    }
                    sqlite3_reset(upd);
                }
                sqlite3_finalize(upd);
            };

            if (version < 2) {
                wrap_table(s->impl_->inbox_key,
                    "SELECT envelope_id, plaintext FROM inbox;",
                    "UPDATE inbox SET plaintext = ? WHERE envelope_id = ?;",
                    {0}, 1);
                wrap_table(s->impl_->outbox_key,
                    "SELECT envelope_id, ciphertext FROM outbox;",
                    "UPDATE outbox SET ciphertext = ? WHERE envelope_id = ?;",
                    {0}, 1);
            }
            // v2 → v3: wrap the remaining sensitive tables.
            wrap_table(s->impl_->sessions_key,
                "SELECT peer_pub, blob FROM sessions;",
                "UPDATE sessions SET blob = ? WHERE peer_pub = ?;",
                {0}, 1);
            wrap_table(s->impl_->chan_state_key,
                "SELECT name, own_dist FROM chan_state WHERE own_dist IS NOT NULL;",
                "UPDATE chan_state SET own_dist = ? WHERE name = ?;",
                {0}, 1);
            wrap_table(s->impl_->chan_peers_key,
                "SELECT channel_id, peer_pub, peer_dist FROM chan_peers;",
                "UPDATE chan_peers SET peer_dist = ? "
                    "WHERE channel_id = ? AND peer_pub = ?;",
                {0, 1}, 2);
            // chan_inbox is a special case: PK is autoinc `id`, but we
            // want to bind AAD = channel_id (so a row can't be moved to
            // a different channel). The wrap_table helper requires
            // AAD-cols == WHERE-cols, so we inline this one.
            {
                struct Row { std::int64_t id;
                             std::vector<std::uint8_t> chan_id;
                             std::vector<std::uint8_t> pt; };
                std::vector<Row> rows;
                sqlite3_stmt* sel = s->impl_->prep(
                    "SELECT id, channel_id, plaintext FROM chan_inbox;");
                while (sqlite3_step(sel) == SQLITE_ROW) {
                    Row r;
                    r.id = sqlite3_column_int64(sel, 0);
                    const auto* cp = static_cast<const std::uint8_t*>(
                        sqlite3_column_blob(sel, 1));
                    r.chan_id.assign(cp, cp + sqlite3_column_bytes(sel, 1));
                    const auto* pp = static_cast<const std::uint8_t*>(
                        sqlite3_column_blob(sel, 2));
                    r.pt.assign(pp, pp + sqlite3_column_bytes(sel, 2));
                    rows.push_back(std::move(r));
                }
                sqlite3_finalize(sel);
                sqlite3_stmt* upd = s->impl_->prep(
                    "UPDATE chan_inbox SET plaintext = ? WHERE id = ?;");
                for (const auto& r : rows) {
                    auto wrapped = aead_wrap(s->impl_->chan_inbox_key,
                        std::span<const std::uint8_t>(r.pt.data(), r.pt.size()),
                        std::span<const std::uint8_t>(r.chan_id.data(),
                                                       r.chan_id.size()));
                    sqlite3_bind_blob(upd, 1, wrapped.data(),
                                      static_cast<int>(wrapped.size()),
                                      SQLITE_TRANSIENT);
                    sqlite3_bind_int64(upd, 2, r.id);
                    if (sqlite3_step(upd) != SQLITE_DONE) {
                        sqlite3_finalize(upd);
                        throw std::runtime_error(
                            "migration: chan_inbox UPDATE failed");
                    }
                    sqlite3_reset(upd);
                }
                sqlite3_finalize(upd);
            }
            wrap_table(s->impl_->peer_name_key,
                "SELECT peer_pub, username FROM peer_name_cache;",
                "UPDATE peer_name_cache SET username = ? WHERE peer_pub = ?;",
                {0}, 1);

            s->impl_->exec("PRAGMA user_version = 3;");
            s->impl_->exec("COMMIT;");
        } catch (...) {
            s->impl_->exec("ROLLBACK;");
            throw;
        }
    }
    return s;
}

namespace {

void bind_blob(sqlite3_stmt* stmt, int idx, std::span<const std::uint8_t> b) {
    sqlite3_bind_blob(stmt, idx, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
}

std::vector<std::uint8_t> column_blob(sqlite3_stmt* stmt, int idx) {
    const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt, idx));
    const int n = sqlite3_column_bytes(stmt, idx);
    return std::vector<std::uint8_t>(p, p + n);
}

}  // namespace

void SqliteStore::save_identity(std::span<const std::uint8_t> pub,
                                std::span<const std::uint8_t> sec, const std::string& username) {
    auto* stmt = impl_->prep(
        "INSERT OR REPLACE INTO identities(username, pub, sec) VALUES(?, ?, ?);");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(stmt, 2, pub);
    bind_blob(stmt, 3, sec);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw_sqlite("save_identity", impl_->db);
    }
    sqlite3_finalize(stmt);
}

std::optional<std::vector<std::uint8_t>> SqliteStore::load_identity_pub(
    const std::string& username) const {
    auto* stmt = impl_->prep("SELECT pub FROM identities WHERE username = ?;");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) out = column_blob(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

std::optional<std::vector<std::uint8_t>> SqliteStore::load_identity_sec(
    const std::string& username) const {
    auto* stmt = impl_->prep("SELECT sec FROM identities WHERE username = ?;");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) out = column_blob(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::remember_peer(std::span<const std::uint8_t> peer_pub,
                                const std::string& username) {
    auto* stmt = impl_->prep(
        "INSERT OR REPLACE INTO peer_keys(username, pub) VALUES(?, ?);");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(stmt, 2, peer_pub);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<std::vector<std::uint8_t>> SqliteStore::lookup_peer(
    const std::string& username) const {
    auto* stmt = impl_->prep("SELECT pub FROM peer_keys WHERE username = ?;");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) out = column_blob(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::save_session(std::span<const std::uint8_t> peer_pub,
                               std::span<const std::uint8_t> blob) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = blob;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->sessions_key, blob, peer_pub);
        stored  = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT OR REPLACE INTO sessions(peer_pub, blob, updated_ms) VALUES(?, ?, "
        "(strftime('%s','now') * 1000));");
    bind_blob(stmt, 1, peer_pub);
    bind_blob(stmt, 2, stored);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw_sqlite("save_session", impl_->db);
    }
    sqlite3_finalize(stmt);
}

std::optional<std::vector<std::uint8_t>> SqliteStore::load_session(
    std::span<const std::uint8_t> peer_pub) const {
    auto* stmt = impl_->prep("SELECT blob FROM sessions WHERE peer_pub = ?;");
    bind_blob(stmt, 1, peer_pub);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto stored = column_blob(stmt, 0);
        if (impl_->encrypt_at_rest) {
            auto pt = aead_unwrap(impl_->sessions_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                peer_pub);
            if (pt) out = std::move(*pt);
        } else {
            out = std::move(stored);
        }
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::append_inbox(std::span<const std::uint8_t> envelope_id,
                               std::span<const std::uint8_t> peer_pub,
                               std::span<const std::uint8_t> plaintext,
                               std::uint64_t timestamp_ms) {
    // When at-rest encryption is on, wrap the plaintext column with the
    // inbox sub-key and bind envelope_id as AAD so a row can't be moved.
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = plaintext;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->inbox_key, plaintext, envelope_id);
        stored  = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT OR IGNORE INTO inbox(envelope_id, peer_pub, plaintext, ts_ms) VALUES(?, ?, ?, "
        "?);");
    bind_blob(stmt, 1, envelope_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void SqliteStore::append_inbox_with_expiry(std::span<const std::uint8_t> envelope_id,
                                            std::span<const std::uint8_t> peer_pub,
                                            std::span<const std::uint8_t> plaintext,
                                            std::uint64_t timestamp_ms,
                                            std::uint64_t expires_at_ms) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = plaintext;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->inbox_key, plaintext, envelope_id);
        stored  = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT OR IGNORE INTO inbox(envelope_id, peer_pub, plaintext, ts_ms, expires_at_ms) "
        "VALUES(?, ?, ?, ?, ?);");
    bind_blob(stmt, 1, envelope_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(expires_at_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void SqliteStore::append_outbox(std::span<const std::uint8_t> envelope_id,
                                std::span<const std::uint8_t> peer_pub,
                                std::span<const std::uint8_t> ciphertext,
                                std::uint64_t timestamp_ms) {
    // The column is named `ciphertext` but historically held plaintext
    // bytes (see chat_client.cpp comment). With at-rest encryption on,
    // it now stores genuine ciphertext: nonce || aead(plaintext, AAD =
    // envelope_id), wrapped under the outbox sub-key.
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = ciphertext;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->outbox_key, ciphertext, envelope_id);
        stored  = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT OR IGNORE INTO outbox(envelope_id, peer_pub, ciphertext, ts_ms) VALUES(?, ?, ?, "
        "?);");
    bind_blob(stmt, 1, envelope_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void SqliteStore::append_outbox_with_expiry(std::span<const std::uint8_t> envelope_id,
                                             std::span<const std::uint8_t> peer_pub,
                                             std::span<const std::uint8_t> ciphertext,
                                             std::uint64_t timestamp_ms,
                                             std::uint64_t expires_at_ms) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = ciphertext;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->outbox_key, ciphertext, envelope_id);
        stored  = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT OR IGNORE INTO outbox(envelope_id, peer_pub, ciphertext, ts_ms, expires_at_ms) "
        "VALUES(?, ?, ?, ?, ?);");
    bind_blob(stmt, 1, envelope_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(expires_at_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::size_t SqliteStore::prune_expired(std::uint64_t now_ms) {
    // Sweep both tables in one transaction. Rows with expires_at_ms = 0
    // (the default, set by the legacy append_* overloads) are exempt.
    impl_->exec("BEGIN;");
    std::size_t deleted = 0;
    for (const char* table : {"inbox", "outbox"}) {
        std::string sql = "DELETE FROM ";
        sql += table;
        sql += " WHERE expires_at_ms > 0 AND expires_at_ms <= ?;";
        auto* stmt = impl_->prep(sql.c_str());
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now_ms));
        sqlite3_step(stmt);
        deleted += static_cast<std::size_t>(sqlite3_changes(impl_->db));
        sqlite3_finalize(stmt);
    }
    impl_->exec("COMMIT;");
    return deleted;
}

void SqliteStore::set_peer_verified(std::span<const std::uint8_t> peer_pub,
                                     bool verified, std::uint64_t verified_at_ms) {
    auto* stmt = impl_->prep(
        "INSERT INTO peer_verified(peer_pub, verified, verified_at_ms) "
        "VALUES(?, ?, ?) ON CONFLICT(peer_pub) DO UPDATE SET "
        "verified = excluded.verified, verified_at_ms = excluded.verified_at_ms;");
    bind_blob(stmt, 1, peer_pub);
    sqlite3_bind_int(stmt, 2, verified ? 1 : 0);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(verified_at_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool SqliteStore::peer_verified(std::span<const std::uint8_t> peer_pub) const {
    auto* stmt = impl_->prep(
        "SELECT verified FROM peer_verified WHERE peer_pub = ?;");
    bind_blob(stmt, 1, peer_pub);
    bool out = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = sqlite3_column_int(stmt, 0) != 0;
    }
    sqlite3_finalize(stmt);
    return out;
}

// ---- Shamir held-share custody --------------------------------------------

void SqliteStore::save_shamir_share(const ShamirHeldShare& s) {
    auto* stmt = impl_->prep(
        "INSERT INTO shamir_held_shares(peer_pub, setup_id, share, threshold, "
        "total, label, received_at_ms) VALUES(?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(peer_pub, setup_id) DO UPDATE SET "
        "share = excluded.share, threshold = excluded.threshold, "
        "total = excluded.total, label = excluded.label, "
        "received_at_ms = excluded.received_at_ms;");
    bind_blob(stmt, 1,
        std::span<const std::uint8_t>(s.peer_pub.data(), s.peer_pub.size()));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(s.setup_id));
    bind_blob(stmt, 3,
        std::span<const std::uint8_t>(s.share.data(), s.share.size()));
    sqlite3_bind_int(stmt, 4, static_cast<int>(s.threshold));
    sqlite3_bind_int(stmt, 5, static_cast<int>(s.total));
    sqlite3_bind_text(stmt, 6, s.label.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(s.received_at_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<SqliteStore::ShamirHeldShare>
SqliteStore::load_shamir_share(std::span<const std::uint8_t> peer_pub,
                                std::uint64_t setup_id) const {
    auto* stmt = impl_->prep(
        "SELECT share, threshold, total, label, received_at_ms FROM "
        "shamir_held_shares WHERE peer_pub = ? AND setup_id = ?;");
    bind_blob(stmt, 1, peer_pub);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(setup_id));
    std::optional<ShamirHeldShare> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ShamirHeldShare s;
        s.peer_pub.assign(peer_pub.begin(), peer_pub.end());
        s.setup_id = setup_id;
        const auto sh_len = sqlite3_column_bytes(stmt, 0);
        const auto* sh_ptr = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        s.share.assign(sh_ptr, sh_ptr + sh_len);
        s.threshold      = static_cast<std::uint32_t>(sqlite3_column_int(stmt, 1));
        s.total          = static_cast<std::uint32_t>(sqlite3_column_int(stmt, 2));
        const auto* lbl  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        s.label          = lbl ? lbl : "";
        s.received_at_ms = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 4));
        out = std::move(s);
    }
    sqlite3_finalize(stmt);
    return out;
}

std::vector<SqliteStore::ShamirHeldShare> SqliteStore::list_shamir_shares() const {
    auto* stmt = impl_->prep(
        "SELECT peer_pub, setup_id, share, threshold, total, label, "
        "received_at_ms FROM shamir_held_shares ORDER BY received_at_ms DESC;");
    std::vector<ShamirHeldShare> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ShamirHeldShare s;
        const auto pp_len = sqlite3_column_bytes(stmt, 0);
        const auto* pp_ptr = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(stmt, 0));
        s.peer_pub.assign(pp_ptr, pp_ptr + pp_len);
        s.setup_id = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
        const auto sh_len = sqlite3_column_bytes(stmt, 2);
        const auto* sh_ptr = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(stmt, 2));
        s.share.assign(sh_ptr, sh_ptr + sh_len);
        s.threshold      = static_cast<std::uint32_t>(sqlite3_column_int(stmt, 3));
        s.total          = static_cast<std::uint32_t>(sqlite3_column_int(stmt, 4));
        const auto* lbl  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        s.label          = lbl ? lbl : "";
        s.received_at_ms = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 6));
        out.push_back(std::move(s));
    }
    sqlite3_finalize(stmt);
    return out;
}

std::size_t SqliteStore::rotate_storage_keys() {
    if (!impl_->encrypt_at_rest || !impl_->have_master) return 0;

    // Fresh random sub-keys for the three rotated tables. (chan_* /
    // mls_* / peer_name use the deterministic sub-keys from open() — a
    // follow-on commit rotates them too.)
    std::array<std::uint8_t, kKeyLen> new_inbox{};
    std::array<std::uint8_t, kKeyLen> new_outbox{};
    std::array<std::uint8_t, kKeyLen> new_sessions{};
    randombytes_buf(new_inbox.data(),    new_inbox.size());
    randombytes_buf(new_outbox.data(),   new_outbox.size());
    randombytes_buf(new_sessions.data(), new_sessions.size());

    const std::uint64_t new_gen = impl_->storage_keys_generation + 1;

    // Re-wrap helper: read each row from `table.col` (AAD = aad_col),
    // unwrap under old_k, re-wrap under new_k, UPDATE the column. The
    // AAD is whatever the original append-path used (envelope_id for
    // inbox/outbox, peer_pub for sessions).
    auto rewrap_table = [&](const char* table, const char* val_col,
                             const char* aad_col,
                             const std::array<std::uint8_t, kKeyLen>& old_k,
                             const std::array<std::uint8_t, kKeyLen>& new_k,
                             std::size_t* counter) {
        std::string sel = "SELECT rowid, ";
        sel += val_col; sel += ", "; sel += aad_col; sel += " FROM ";
        sel += table; sel += ";";
        auto* sel_stmt = impl_->prep(sel.c_str());

        struct Pending {
            sqlite3_int64 rowid;
            std::vector<std::uint8_t> new_blob;
        };
        std::vector<Pending> pending;
        while (sqlite3_step(sel_stmt) == SQLITE_ROW) {
            const auto rid       = sqlite3_column_int64(sel_stmt, 0);
            const auto val_len   = sqlite3_column_bytes(sel_stmt, 1);
            const auto* val_ptr  = static_cast<const std::uint8_t*>(
                sqlite3_column_blob(sel_stmt, 1));
            const auto aad_len   = sqlite3_column_bytes(sel_stmt, 2);
            const auto* aad_ptr  = static_cast<const std::uint8_t*>(
                sqlite3_column_blob(sel_stmt, 2));
            auto unwrapped = aead_unwrap(
                old_k,
                std::span<const std::uint8_t>(val_ptr, static_cast<std::size_t>(val_len)),
                std::span<const std::uint8_t>(aad_ptr, static_cast<std::size_t>(aad_len)));
            if (!unwrapped) {
                // A row that doesn't unwrap under the current key is
                // already corrupt or from a different key generation —
                // skip rather than crash; the caller's log surfaces
                // the rewrap count vs row count mismatch.
                continue;
            }
            auto rewrapped = aead_wrap(
                new_k,
                std::span<const std::uint8_t>(unwrapped->data(), unwrapped->size()),
                std::span<const std::uint8_t>(aad_ptr, static_cast<std::size_t>(aad_len)));
            pending.push_back({rid, std::move(rewrapped)});
            sodium_memzero(unwrapped->data(), unwrapped->size());
        }
        sqlite3_finalize(sel_stmt);

        std::string upd = "UPDATE ";
        upd += table; upd += " SET "; upd += val_col;
        upd += " = ? WHERE rowid = ?;";
        for (const auto& p : pending) {
            auto* upd_stmt = impl_->prep(upd.c_str());
            sqlite3_bind_blob(upd_stmt, 1, p.new_blob.data(),
                              static_cast<int>(p.new_blob.size()),
                              SQLITE_TRANSIENT);
            sqlite3_bind_int64(upd_stmt, 2, p.rowid);
            sqlite3_step(upd_stmt);
            sqlite3_finalize(upd_stmt);
            ++*counter;
        }
    };

    auto persist_wrapped = [&](const char* name,
                                const std::array<std::uint8_t, kKeyLen>& k) {
        std::vector<std::uint8_t> aad;
        aad.insert(aad.end(),
                    reinterpret_cast<const std::uint8_t*>(name),
                    reinterpret_cast<const std::uint8_t*>(name) + std::strlen(name));
        for (int i = 7; i >= 0; --i) {
            aad.push_back(static_cast<std::uint8_t>((new_gen >> (8 * i)) & 0xff));
        }
        auto wrapped = aead_wrap(
            impl_->master_key,
            std::span<const std::uint8_t>(k.data(), k.size()),
            std::span<const std::uint8_t>(aad.data(), aad.size()));
        auto* stmt = impl_->prep(
            "INSERT INTO storage_keys(name, wrapped, generation) VALUES(?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET wrapped = excluded.wrapped, "
            "generation = excluded.generation;");
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, wrapped.data(),
                          static_cast<int>(wrapped.size()), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(new_gen));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    };

    std::size_t total = 0;
    impl_->exec("BEGIN;");
    try {
        rewrap_table("inbox",    "plaintext",  "envelope_id",
                      impl_->inbox_key,    new_inbox,    &total);
        rewrap_table("outbox",   "ciphertext", "envelope_id",
                      impl_->outbox_key,   new_outbox,   &total);
        rewrap_table("sessions", "blob",       "peer_pub",
                      impl_->sessions_key, new_sessions, &total);
        persist_wrapped("inbox",    new_inbox);
        persist_wrapped("outbox",   new_outbox);
        persist_wrapped("sessions", new_sessions);
        impl_->exec("COMMIT;");
    } catch (...) {
        impl_->exec("ROLLBACK;");
        sodium_memzero(new_inbox.data(),    new_inbox.size());
        sodium_memzero(new_outbox.data(),   new_outbox.size());
        sodium_memzero(new_sessions.data(), new_sessions.size());
        throw;
    }

    // Atomic key swap. Zero the predecessors so a memory dump after this
    // point cannot recover them.
    sodium_memzero(impl_->inbox_key.data(),    impl_->inbox_key.size());
    sodium_memzero(impl_->outbox_key.data(),   impl_->outbox_key.size());
    sodium_memzero(impl_->sessions_key.data(), impl_->sessions_key.size());
    impl_->inbox_key    = new_inbox;
    impl_->outbox_key   = new_outbox;
    impl_->sessions_key = new_sessions;
    impl_->storage_keys_generation = new_gen;
    sodium_memzero(new_inbox.data(),    new_inbox.size());
    sodium_memzero(new_outbox.data(),   new_outbox.size());
    sodium_memzero(new_sessions.data(), new_sessions.size());
    return total;
}

std::vector<SqliteStore::InboxRow> SqliteStore::recent_inbox(std::size_t limit) const {
    auto* stmt =
        impl_->prep("SELECT envelope_id, peer_pub, plaintext, ts_ms FROM inbox "
                    "ORDER BY ts_ms DESC LIMIT ?;");
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(limit));
    std::vector<InboxRow> rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        InboxRow r;
        r.envelope_id = column_blob(stmt, 0);
        r.peer_pub = column_blob(stmt, 1);
        auto stored = column_blob(stmt, 2);
        if (impl_->encrypt_at_rest) {
            auto pt = aead_unwrap(impl_->inbox_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                std::span<const std::uint8_t>(r.envelope_id.data(),
                                               r.envelope_id.size()));
            if (!pt) {
                // Skip corrupted / wrong-key rows rather than abort —
                // surfaces as a missing entry in history rather than a
                // crash. The user notices and we log nothing here
                // (would dilute the canary-grep blindness check).
                continue;
            }
            r.plaintext = std::move(*pt);
        } else {
            r.plaintext = std::move(stored);
        }
        r.timestamp_ms = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return rows;
}

std::vector<SqliteStore::OutboxRow> SqliteStore::recent_outbox(std::size_t limit) const {
    auto* stmt =
        impl_->prep("SELECT envelope_id, peer_pub, ciphertext, ts_ms FROM outbox "
                    "ORDER BY ts_ms DESC LIMIT ?;");
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(limit));
    std::vector<OutboxRow> rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        OutboxRow r;
        r.envelope_id = column_blob(stmt, 0);
        r.peer_pub = column_blob(stmt, 1);
        auto stored = column_blob(stmt, 2);
        if (impl_->encrypt_at_rest) {
            auto pt = aead_unwrap(impl_->outbox_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                std::span<const std::uint8_t>(r.envelope_id.data(),
                                               r.envelope_id.size()));
            if (!pt) continue;
            r.plaintext = std::move(*pt);
        } else {
            r.plaintext = std::move(stored);
        }
        r.timestamp_ms = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return rows;
}

void SqliteStore::record_carry(std::span<const std::uint8_t> peer_pub,
                               std::int64_t delta_bytes) {
    auto* stmt = impl_->prep(
        "INSERT INTO carry_ledger(peer_pub, delta_bytes) VALUES(?, ?) "
        "ON CONFLICT(peer_pub) DO UPDATE SET delta_bytes = delta_bytes + excluded.delta_bytes;");
    bind_blob(stmt, 1, peer_pub);
    sqlite3_bind_int64(stmt, 2, delta_bytes);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::int64_t SqliteStore::carry_balance(std::span<const std::uint8_t> peer_pub) const {
    auto* stmt = impl_->prep("SELECT delta_bytes FROM carry_ledger WHERE peer_pub = ?;");
    bind_blob(stmt, 1, peer_pub);
    std::int64_t out = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) out = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::srv_offline_enqueue(std::span<const std::uint8_t> recipient_pub,
                                      std::span<const std::uint8_t> envelope_bytes,
                                      std::uint64_t timestamp_ms) {
    auto* stmt = impl_->prep(
        "INSERT INTO srv_offline(recipient_pub, envelope, ts_ms) VALUES(?, ?, ?);");
    bind_blob(stmt, 1, recipient_pub);
    bind_blob(stmt, 2, envelope_bytes);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(timestamp_ms));
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw_sqlite("srv_offline_enqueue", impl_->db);
    }
    sqlite3_finalize(stmt);
}

void SqliteStore::srv_register_user(const std::string& username,
                                     std::span<const std::uint8_t> pubkey) {
    auto* stmt = impl_->prep(
        "INSERT INTO srv_directory(username, pubkey) VALUES(?, ?) "
        "ON CONFLICT(username) DO UPDATE SET pubkey = excluded.pubkey;");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(stmt, 2, pubkey);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<std::vector<std::uint8_t>> SqliteStore::srv_resolve_username(
    const std::string& username) const {
    auto* stmt = impl_->prep("SELECT pubkey FROM srv_directory WHERE username = ?;");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) out = column_blob(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

std::optional<std::string> SqliteStore::srv_reverse_resolve_pubkey(
    std::span<const std::uint8_t> pubkey) const {
    auto* stmt = impl_->prep("SELECT username FROM srv_directory WHERE pubkey = ? LIMIT 1;");
    bind_blob(stmt, 1, pubkey);
    std::optional<std::string> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const auto* s = sqlite3_column_text(stmt, 0);
        if (s) out = reinterpret_cast<const char*>(s);
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::srv_put_prekey_bundle(std::span<const std::uint8_t> owner_pub,
                                        std::span<const std::uint8_t> bundle_blob) {
    auto* stmt = impl_->prep(
        "INSERT INTO srv_prekey_bundles(owner_pub, bundle, updated_ms) VALUES(?, ?, "
        "(strftime('%s','now') * 1000)) "
        "ON CONFLICT(owner_pub) DO UPDATE SET bundle = excluded.bundle, "
        "updated_ms = excluded.updated_ms;");
    bind_blob(stmt, 1, owner_pub);
    bind_blob(stmt, 2, bundle_blob);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<std::vector<std::uint8_t>> SqliteStore::srv_get_prekey_bundle(
    std::span<const std::uint8_t> owner_pub) const {
    auto* stmt = impl_->prep("SELECT bundle FROM srv_prekey_bundles WHERE owner_pub = ?;");
    bind_blob(stmt, 1, owner_pub);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) out = column_blob(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::chan_save(const std::string& name, std::span<const std::uint8_t> channel_id,
                             std::span<const std::uint8_t> own_dist,
                             ChannelCrypto crypto) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = own_dist;
    if (impl_->encrypt_at_rest && !own_dist.empty()) {
        const auto* nm = reinterpret_cast<const std::uint8_t*>(name.data());
        wrapped = aead_wrap(impl_->chan_state_key, own_dist,
            std::span<const std::uint8_t>(nm, name.size()));
        stored = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT INTO chan_state(name, channel_id, own_dist, crypto) "
        "VALUES(?, ?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET channel_id = excluded.channel_id, "
        "own_dist = excluded.own_dist, crypto = excluded.crypto;");
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(stmt, 2, channel_id);
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int(stmt, 4, static_cast<int>(crypto));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<SqliteStore::ChannelRow> SqliteStore::chan_list() const {
    auto* stmt = impl_->prep(
        "SELECT name, channel_id, own_dist, crypto FROM chan_state "
        "ORDER BY name;");
    std::vector<ChannelRow> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ChannelRow r;
        const auto* nm = sqlite3_column_text(stmt, 0);
        if (nm) r.name = reinterpret_cast<const char*>(nm);
        r.channel_id = column_blob(stmt, 1);
        auto stored = column_blob(stmt, 2);
        if (impl_->encrypt_at_rest && !stored.empty()) {
            const auto* nb = reinterpret_cast<const std::uint8_t*>(r.name.data());
            auto pt = aead_unwrap(impl_->chan_state_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                std::span<const std::uint8_t>(nb, r.name.size()));
            if (pt) r.own_dist = std::move(*pt);
            // else: drop silently — channel will be unrecoverable but
            // we don't crash the entire chan_list scan.
        } else {
            r.own_dist = std::move(stored);
        }
        const int c = sqlite3_column_int(stmt, 3);
        r.crypto = (c == 1) ? ChannelCrypto::kMls : ChannelCrypto::kSenderKeys;
        out.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::chan_save_peer(std::span<const std::uint8_t> channel_id,
                                  std::span<const std::uint8_t> peer_pub,
                                  std::span<const std::uint8_t> peer_dist) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = peer_dist;
    if (impl_->encrypt_at_rest) {
        // AAD = channel_id || peer_pub.
        std::vector<std::uint8_t> aad;
        aad.reserve(channel_id.size() + peer_pub.size());
        aad.insert(aad.end(), channel_id.begin(), channel_id.end());
        aad.insert(aad.end(), peer_pub.begin(), peer_pub.end());
        wrapped = aead_wrap(impl_->chan_peers_key, peer_dist,
            std::span<const std::uint8_t>(aad.data(), aad.size()));
        stored = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT INTO chan_peers(channel_id, peer_pub, peer_dist) VALUES(?, ?, ?) "
        "ON CONFLICT(channel_id, peer_pub) DO UPDATE SET peer_dist = excluded.peer_dist;");
    bind_blob(stmt, 1, channel_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, stored);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<SqliteStore::ChannelPeerRow> SqliteStore::chan_peers(
    std::span<const std::uint8_t> channel_id) const {
    auto* stmt = impl_->prep(
        "SELECT peer_pub, peer_dist FROM chan_peers WHERE channel_id = ?;");
    bind_blob(stmt, 1, channel_id);
    std::vector<ChannelPeerRow> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ChannelPeerRow r;
        r.peer_pub = column_blob(stmt, 0);
        auto stored = column_blob(stmt, 1);
        if (impl_->encrypt_at_rest) {
            std::vector<std::uint8_t> aad;
            aad.reserve(channel_id.size() + r.peer_pub.size());
            aad.insert(aad.end(), channel_id.begin(), channel_id.end());
            aad.insert(aad.end(), r.peer_pub.begin(), r.peer_pub.end());
            auto pt = aead_unwrap(impl_->chan_peers_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                std::span<const std::uint8_t>(aad.data(), aad.size()));
            if (!pt) continue;
            r.peer_dist = std::move(*pt);
        } else {
            r.peer_dist = std::move(stored);
        }
        out.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::chan_append_inbox(std::span<const std::uint8_t> channel_id,
                                     std::span<const std::uint8_t> sender_pub,
                                     std::span<const std::uint8_t> plaintext,
                                     std::uint64_t timestamp_ms) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = plaintext;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->chan_inbox_key, plaintext, channel_id);
        stored = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT INTO chan_inbox(channel_id, sender_pub, plaintext, ts_ms) "
        "VALUES(?, ?, ?, ?);");
    bind_blob(stmt, 1, channel_id);
    bind_blob(stmt, 2, sender_pub);
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void SqliteStore::chan_delete(const std::string& name,
                              std::span<const std::uint8_t> channel_id) {
    impl_->exec("BEGIN");
    auto exec_one = [&](const char* sql, auto bind_fn) {
        auto* stmt = impl_->prep(sql);
        bind_fn(stmt);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    };
    exec_one("DELETE FROM chan_state WHERE name = ?;", [&](sqlite3_stmt* s) {
        sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    });
    exec_one("DELETE FROM chan_peers WHERE channel_id = ?;",
             [&](sqlite3_stmt* s) { bind_blob(s, 1, channel_id); });
    exec_one("DELETE FROM chan_inbox WHERE channel_id = ?;",
             [&](sqlite3_stmt* s) { bind_blob(s, 1, channel_id); });
    exec_one("DELETE FROM mls_group_state WHERE channel_id = ?;",
             [&](sqlite3_stmt* s) { bind_blob(s, 1, channel_id); });
    exec_one("DELETE FROM mls_group_log WHERE channel_id = ?;",
             [&](sqlite3_stmt* s) { bind_blob(s, 1, channel_id); });
    // Drop the GroupSession blob too (stored under sessions/__chanstate__:<name>).
    const std::string state_key = "__chanstate__:" + name;
    exec_one("DELETE FROM sessions WHERE peer_pub = ?;",
             [&](sqlite3_stmt* s) {
                 bind_blob(s, 1, std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t*>(state_key.data()),
                                     state_key.size()));
             });
    impl_->exec("COMMIT");
}

std::vector<SqliteStore::ChannelInboxRow> SqliteStore::chan_recent_inbox(
    std::span<const std::uint8_t> channel_id, std::size_t limit) const {
    auto* stmt = impl_->prep(
        "SELECT channel_id, sender_pub, plaintext, ts_ms FROM chan_inbox "
        "WHERE channel_id = ? ORDER BY ts_ms DESC LIMIT ?;");
    bind_blob(stmt, 1, channel_id);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(limit));
    std::vector<ChannelInboxRow> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ChannelInboxRow r;
        r.channel_id = column_blob(stmt, 0);
        r.sender_pub = column_blob(stmt, 1);
        auto stored = column_blob(stmt, 2);
        if (impl_->encrypt_at_rest) {
            auto pt = aead_unwrap(impl_->chan_inbox_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                std::span<const std::uint8_t>(r.channel_id.data(),
                                               r.channel_id.size()));
            if (!pt) continue;
            r.plaintext = std::move(*pt);
        } else {
            r.plaintext = std::move(stored);
        }
        r.timestamp_ms = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
        out.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::cache_peer_name(std::span<const std::uint8_t> peer_pub,
                                   const std::string& username) {
    auto* stmt = impl_->prep(
        "INSERT INTO peer_name_cache(peer_pub, username, learned_ms) VALUES(?, ?, "
        "(strftime('%s','now') * 1000)) "
        "ON CONFLICT(peer_pub) DO UPDATE SET username = excluded.username, "
        "learned_ms = excluded.learned_ms;");
    bind_blob(stmt, 1, peer_pub);
    if (impl_->encrypt_at_rest) {
        const auto* up = reinterpret_cast<const std::uint8_t*>(username.data());
        auto wrapped = aead_wrap(impl_->peer_name_key,
            std::span<const std::uint8_t>(up, username.size()), peer_pub);
        sqlite3_bind_blob(stmt, 2, wrapped.data(),
                          static_cast<int>(wrapped.size()), SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<std::string> SqliteStore::peer_name(std::span<const std::uint8_t> peer_pub) const {
    auto* stmt = impl_->prep("SELECT username FROM peer_name_cache WHERE peer_pub = ?;");
    bind_blob(stmt, 1, peer_pub);
    std::optional<std::string> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (impl_->encrypt_at_rest) {
            auto stored = column_blob(stmt, 0);
            auto pt = aead_unwrap(impl_->peer_name_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                peer_pub);
            if (pt) out = std::string(pt->begin(), pt->end());
        } else {
            const auto* s = sqlite3_column_text(stmt, 0);
            if (s) out = reinterpret_cast<const char*>(s);
        }
    }
    sqlite3_finalize(stmt);
    return out;
}

std::vector<SqliteStore::CachedPeer> SqliteStore::all_cached_peers() const {
    auto* stmt = impl_->prep(
        "SELECT peer_pub, username FROM peer_name_cache ORDER BY learned_ms DESC;");
    std::vector<CachedPeer> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CachedPeer p;
        p.peer_pub = column_blob(stmt, 0);
        if (impl_->encrypt_at_rest) {
            auto stored = column_blob(stmt, 1);
            auto pt = aead_unwrap(impl_->peer_name_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                std::span<const std::uint8_t>(p.peer_pub.data(),
                                               p.peer_pub.size()));
            if (!pt) continue;
            p.username = std::string(pt->begin(), pt->end());
        } else {
            const auto* s = sqlite3_column_text(stmt, 1);
            if (s) p.username = reinterpret_cast<const char*>(s);
        }
        out.push_back(std::move(p));
    }
    sqlite3_finalize(stmt);
    return out;
}

std::vector<std::vector<std::uint8_t>> SqliteStore::srv_offline_drain(
    std::span<const std::uint8_t> recipient_pub) {
    auto* stmt = impl_->prep(
        "SELECT id, envelope FROM srv_offline WHERE recipient_pub = ? ORDER BY id ASC;");
    bind_blob(stmt, 1, recipient_pub);
    std::vector<std::vector<std::uint8_t>> out;
    std::vector<sqlite3_int64> ids;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ids.push_back(sqlite3_column_int64(stmt, 0));
        out.push_back(column_blob(stmt, 1));
    }
    sqlite3_finalize(stmt);
    if (ids.empty()) return out;
    // Delete drained rows in one transaction.
    impl_->exec("BEGIN");
    auto* del = impl_->prep("DELETE FROM srv_offline WHERE id = ?;");
    for (auto id : ids) {
        sqlite3_bind_int64(del, 1, id);
        sqlite3_step(del);
        sqlite3_reset(del);
    }
    sqlite3_finalize(del);
    impl_->exec("COMMIT");
    return out;
}

// =============================================================================
// MLS persistence (operation-replay model). Two paired tables wrapped at
// rest with separate per-table HKDF subkeys; AAD binds rows to their
// channel + sequence so a row can't be silently moved or reordered.
// =============================================================================

namespace {
// AAD for log rows = channel_id || seq encoded as 8 bytes big-endian.
// Binding the seq prevents an attacker who can swap encrypted blobs
// from reordering ops within the same channel; binding the channel
// prevents cross-channel substitution.
std::vector<std::uint8_t> mls_log_aad(std::span<const std::uint8_t> channel_id,
                                       std::int64_t seq) {
    std::vector<std::uint8_t> out;
    out.reserve(channel_id.size() + 8);
    out.insert(out.end(), channel_id.begin(), channel_id.end());
    auto u = static_cast<std::uint64_t>(seq);
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((u >> (8 * i)) & 0xff));
    }
    return out;
}
}  // namespace

void SqliteStore::mls_group_save(std::span<const std::uint8_t> channel_id,
                                  std::span<const std::uint8_t> seed_blob) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = seed_blob;
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->mls_state_key, seed_blob, channel_id);
        stored = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    auto* stmt = impl_->prep(
        "INSERT INTO mls_group_state (channel_id, seed_blob, created_at_ms) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(channel_id) DO UPDATE SET "
        "  seed_blob = excluded.seed_blob, "
        "  created_at_ms = excluded.created_at_ms;");
    bind_blob(stmt, 1, channel_id);
    bind_blob(stmt, 2, stored);
    sqlite3_bind_int64(stmt, 3,
        static_cast<sqlite3_int64>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void SqliteStore::mls_group_op_append(std::span<const std::uint8_t> channel_id,
                                        std::int64_t seq,
                                        std::span<const std::uint8_t> op_blob) {
    std::vector<std::uint8_t> wrapped;
    std::span<const std::uint8_t> stored = op_blob;
    auto aad_vec = mls_log_aad(channel_id, seq);
    if (impl_->encrypt_at_rest) {
        wrapped = aead_wrap(impl_->mls_log_key, op_blob,
                            std::span<const std::uint8_t>(
                                aad_vec.data(), aad_vec.size()));
        stored = std::span<const std::uint8_t>(wrapped.data(), wrapped.size());
    }
    // INSERT-only — duplicate (channel_id, seq) is an error caller should
    // see (means we double-appended for the same op, indicates a bug
    // upstream rather than a benign retry).
    auto* stmt = impl_->prep(
        "INSERT INTO mls_group_log (channel_id, seq, op_blob, applied_at_ms) "
        "VALUES (?, ?, ?, ?);");
    bind_blob(stmt, 1, channel_id);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(seq));
    bind_blob(stmt, 3, stored);
    sqlite3_bind_int64(stmt, 4,
        static_cast<sqlite3_int64>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        const std::string err = sqlite3_errmsg(impl_->db);
        sqlite3_finalize(stmt);
        throw std::runtime_error("mls_group_op_append: " + err);
    }
    sqlite3_finalize(stmt);
}

std::optional<SqliteStore::MlsGroupSnapshot> SqliteStore::mls_group_load(
    std::span<const std::uint8_t> channel_id) const {
    MlsGroupSnapshot snap;

    // 1. Seed.
    {
        auto* stmt = impl_->prep(
            "SELECT seed_blob FROM mls_group_state WHERE channel_id = ?;");
        bind_blob(stmt, 1, channel_id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return std::nullopt;
        }
        auto stored = column_blob(stmt, 0);
        sqlite3_finalize(stmt);
        if (impl_->encrypt_at_rest) {
            auto pt = aead_unwrap(impl_->mls_state_key,
                std::span<const std::uint8_t>(stored.data(), stored.size()),
                channel_id);
            if (!pt) {
                throw std::runtime_error(
                    "mls_group_load: seed AEAD verify failed (corruption "
                    "or wrong master_key)");
            }
            snap.seed = std::move(*pt);
        } else {
            snap.seed = std::move(stored);
        }
    }

    // 2. Ops in seq order.
    {
        auto* stmt = impl_->prep(
            "SELECT seq, op_blob FROM mls_group_log "
            "WHERE channel_id = ? ORDER BY seq ASC;");
        bind_blob(stmt, 1, channel_id);
        std::int64_t max_seq = -1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::int64_t seq = sqlite3_column_int64(stmt, 0);
            auto stored = column_blob(stmt, 1);
            if (impl_->encrypt_at_rest) {
                auto aad_vec = mls_log_aad(channel_id, seq);
                auto pt = aead_unwrap(impl_->mls_log_key,
                    std::span<const std::uint8_t>(stored.data(), stored.size()),
                    std::span<const std::uint8_t>(aad_vec.data(),
                                                   aad_vec.size()));
                if (!pt) {
                    sqlite3_finalize(stmt);
                    throw std::runtime_error(
                        "mls_group_load: log row AEAD verify failed at seq " +
                        std::to_string(seq));
                }
                snap.ops.push_back(std::move(*pt));
            } else {
                snap.ops.push_back(std::move(stored));
            }
            if (seq > max_seq) max_seq = seq;
        }
        sqlite3_finalize(stmt);
        snap.next_seq = max_seq + 1;
    }
    return snap;
}

void SqliteStore::mls_group_delete(std::span<const std::uint8_t> channel_id) {
    auto exec_one = [&](const char* sql) {
        auto* stmt = impl_->prep(sql);
        bind_blob(stmt, 1, channel_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    };
    impl_->exec("BEGIN");
    exec_one("DELETE FROM mls_group_state WHERE channel_id = ?;");
    exec_one("DELETE FROM mls_group_log WHERE channel_id = ?;");
    impl_->exec("COMMIT");
}

}  // namespace fb::store
