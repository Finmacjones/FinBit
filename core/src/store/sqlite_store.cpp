// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/store/sqlite_store.hpp"

#include <sqlite3.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

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
    own_dist   BLOB
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
)sql";

void throw_sqlite(const std::string& ctx, sqlite3* db) {
    throw std::runtime_error(ctx + ": " + (db ? sqlite3_errmsg(db) : "no db"));
}

}  // namespace

struct SqliteStore::Impl {
    sqlite3* db = nullptr;
    ~Impl() {
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

std::unique_ptr<SqliteStore> SqliteStore::open(const std::string& path,
                                               std::string_view passphrase) {
    auto s = std::unique_ptr<SqliteStore>(new SqliteStore());
    if (sqlite3_open(path.c_str(), &s->impl_->db) != SQLITE_OK) {
        throw_sqlite("open", s->impl_->db);
    }
    if (!passphrase.empty()) {
        // TODO(sqlcipher): when SQLCipher is the underlying lib, run:
        //   sqlite3_key(impl_->db, passphrase.data(), passphrase.size());
        // Plain SQLite has no such symbol; passphrase is silently ignored for
        // Phase 0.
        (void)passphrase;
    }
    s->impl_->exec(kSchema);
    s->impl_->exec("PRAGMA journal_mode = WAL;");
    s->impl_->exec("PRAGMA synchronous = NORMAL;");
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
    auto* stmt = impl_->prep(
        "INSERT OR REPLACE INTO sessions(peer_pub, blob, updated_ms) VALUES(?, ?, "
        "(strftime('%s','now') * 1000));");
    bind_blob(stmt, 1, peer_pub);
    bind_blob(stmt, 2, blob);
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
    if (sqlite3_step(stmt) == SQLITE_ROW) out = column_blob(stmt, 0);
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::append_inbox(std::span<const std::uint8_t> envelope_id,
                               std::span<const std::uint8_t> peer_pub,
                               std::span<const std::uint8_t> plaintext,
                               std::uint64_t timestamp_ms) {
    auto* stmt = impl_->prep(
        "INSERT OR IGNORE INTO inbox(envelope_id, peer_pub, plaintext, ts_ms) VALUES(?, ?, ?, "
        "?);");
    bind_blob(stmt, 1, envelope_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, plaintext);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void SqliteStore::append_outbox(std::span<const std::uint8_t> envelope_id,
                                std::span<const std::uint8_t> peer_pub,
                                std::span<const std::uint8_t> ciphertext,
                                std::uint64_t timestamp_ms) {
    auto* stmt = impl_->prep(
        "INSERT OR IGNORE INTO outbox(envelope_id, peer_pub, ciphertext, ts_ms) VALUES(?, ?, ?, "
        "?);");
    bind_blob(stmt, 1, envelope_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, ciphertext);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(timestamp_ms));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
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
        r.plaintext = column_blob(stmt, 2);
        r.timestamp_ms = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return rows;
}

std::vector<SqliteStore::OutboxRow> SqliteStore::recent_outbox(std::size_t limit) const {
    // Note: column is named `ciphertext` but holds plaintext bytes — see
    // the append_outbox call site comment in chat_client.cpp.
    auto* stmt =
        impl_->prep("SELECT envelope_id, peer_pub, ciphertext, ts_ms FROM outbox "
                    "ORDER BY ts_ms DESC LIMIT ?;");
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(limit));
    std::vector<OutboxRow> rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        OutboxRow r;
        r.envelope_id = column_blob(stmt, 0);
        r.peer_pub = column_blob(stmt, 1);
        r.plaintext = column_blob(stmt, 2);
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
                             std::span<const std::uint8_t> own_dist) {
    auto* stmt = impl_->prep(
        "INSERT INTO chan_state(name, channel_id, own_dist) VALUES(?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET channel_id = excluded.channel_id, "
        "own_dist = excluded.own_dist;");
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(stmt, 2, channel_id);
    bind_blob(stmt, 3, own_dist);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<SqliteStore::ChannelRow> SqliteStore::chan_list() const {
    auto* stmt = impl_->prep("SELECT name, channel_id, own_dist FROM chan_state ORDER BY name;");
    std::vector<ChannelRow> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ChannelRow r;
        const auto* nm = sqlite3_column_text(stmt, 0);
        if (nm) r.name = reinterpret_cast<const char*>(nm);
        r.channel_id = column_blob(stmt, 1);
        r.own_dist = column_blob(stmt, 2);
        out.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::chan_save_peer(std::span<const std::uint8_t> channel_id,
                                  std::span<const std::uint8_t> peer_pub,
                                  std::span<const std::uint8_t> peer_dist) {
    auto* stmt = impl_->prep(
        "INSERT INTO chan_peers(channel_id, peer_pub, peer_dist) VALUES(?, ?, ?) "
        "ON CONFLICT(channel_id, peer_pub) DO UPDATE SET peer_dist = excluded.peer_dist;");
    bind_blob(stmt, 1, channel_id);
    bind_blob(stmt, 2, peer_pub);
    bind_blob(stmt, 3, peer_dist);
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
        r.peer_dist = column_blob(stmt, 1);
        out.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqliteStore::chan_append_inbox(std::span<const std::uint8_t> channel_id,
                                     std::span<const std::uint8_t> sender_pub,
                                     std::span<const std::uint8_t> plaintext,
                                     std::uint64_t timestamp_ms) {
    auto* stmt = impl_->prep(
        "INSERT INTO chan_inbox(channel_id, sender_pub, plaintext, ts_ms) "
        "VALUES(?, ?, ?, ?);");
    bind_blob(stmt, 1, channel_id);
    bind_blob(stmt, 2, sender_pub);
    bind_blob(stmt, 3, plaintext);
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
        r.plaintext = column_blob(stmt, 2);
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
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<std::string> SqliteStore::peer_name(std::span<const std::uint8_t> peer_pub) const {
    auto* stmt = impl_->prep("SELECT username FROM peer_name_cache WHERE peer_pub = ?;");
    bind_blob(stmt, 1, peer_pub);
    std::optional<std::string> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const auto* s = sqlite3_column_text(stmt, 0);
        if (s) out = reinterpret_cast<const char*>(s);
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
        const auto* s = sqlite3_column_text(stmt, 1);
        if (s) p.username = reinterpret_cast<const char*>(s);
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

}  // namespace fb::store
