// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/identity/username_log.hpp"

#include <sodium.h>
#include <sqlite3.h>

#include "identity_log.pb.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace fb::identity {

// ---------------------------------------------------------------------------
// Username validation. ASCII-only v0 namespace: lowercase letters, digits,
// dot, underscore, dash. Length 3..32 bytes. No leading/trailing dot or
// dash (avoids confusion with hidden files / CLI flags).
// ---------------------------------------------------------------------------
bool is_valid_username(std::string_view candidate) {
    if (candidate.size() < kUsernameMinBytes ||
        candidate.size() > kUsernameMaxBytes) {
        return false;
    }
    auto edge_bad = [](char c) { return c == '.' || c == '-'; };
    if (edge_bad(candidate.front()) || edge_bad(candidate.back())) {
        return false;
    }
    for (char c : candidate) {
        const bool ok =
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Canonical signing bytes. Layout chosen so anyone can reproduce them
// without a protobuf decoder:
//
//   "fb.identity.UserClaim:v1\n"
//   uint16_be(username_len) || username_bytes
//   uint8(pubkey_len = 32)  || pubkey_bytes
//   uint64_be(timestamp_ms)
//   uint8(nonce_len = 16)   || nonce_bytes
//
// Pinning the magic + version means future versions of UserClaim with
// added fields can introduce a new canonical layout without the verify
// path being ambiguous about which one was signed.
// ---------------------------------------------------------------------------
namespace {

constexpr const char* kCanonicalMagic = "fb.identity.UserClaim:v1\n";

void append_be16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}
void append_be64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
}

}  // namespace

std::vector<std::uint8_t> canonical_signing_bytes(
    std::string_view username,
    std::span<const std::uint8_t> pubkey,
    std::uint64_t timestamp_ms,
    std::span<const std::uint8_t> nonce) {
    if (pubkey.size() != 32) {
        throw std::invalid_argument(
            "canonical_signing_bytes: pubkey must be 32 bytes (Ed25519)");
    }
    if (nonce.size() != 16) {
        throw std::invalid_argument(
            "canonical_signing_bytes: nonce must be 16 bytes");
    }
    std::vector<std::uint8_t> out;
    out.reserve(64 + username.size());
    const std::string magic = kCanonicalMagic;
    out.insert(out.end(), magic.begin(), magic.end());
    append_be16(out, static_cast<std::uint16_t>(username.size()));
    out.insert(out.end(), username.begin(), username.end());
    out.push_back(32);
    out.insert(out.end(), pubkey.begin(), pubkey.end());
    append_be64(out, timestamp_ms);
    out.push_back(16);
    out.insert(out.end(), nonce.begin(), nonce.end());
    return out;
}

fb::proto::UserClaim build_claim(
    std::string_view username,
    std::span<const std::uint8_t> sig_pub,
    std::span<const std::uint8_t> sig_priv,
    std::uint64_t timestamp_ms) {
    if (!is_valid_username(username)) {
        throw std::invalid_argument(
            "build_claim: username failed validation (length 3..32, "
            "[a-z0-9._-], no leading/trailing dot or dash)");
    }
    if (sig_pub.size() != crypto_sign_PUBLICKEYBYTES) {
        throw std::invalid_argument(
            "build_claim: sig_pub must be 32 bytes");
    }
    if (sig_priv.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::invalid_argument(
            "build_claim: sig_priv must be 64 bytes");
    }
    fb::proto::UserClaim out;
    out.set_username(std::string(username));
    out.set_pubkey(std::string(sig_pub.begin(), sig_pub.end()));
    out.set_timestamp_ms(timestamp_ms);

    std::array<std::uint8_t, 16> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    out.set_nonce(std::string(nonce.begin(), nonce.end()));

    auto signing_bytes = canonical_signing_bytes(
        username, sig_pub, timestamp_ms,
        std::span<const std::uint8_t>(nonce.data(), nonce.size()));

    std::array<std::uint8_t, crypto_sign_BYTES> sig{};
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              signing_bytes.data(), signing_bytes.size(),
                              sig_priv.data()) != 0) {
        throw std::runtime_error("build_claim: crypto_sign_detached failed");
    }
    out.set_signature(std::string(sig.begin(), sig.begin() + sig_len));
    return out;
}

namespace {

// Verify the claim's signature against its embedded pubkey + canonical
// signing bytes. Returns true on success.
bool verify_claim_signature(const fb::proto::UserClaim& c) {
    if (c.pubkey().size() != crypto_sign_PUBLICKEYBYTES) return false;
    if (c.signature().size() != crypto_sign_BYTES)       return false;
    if (c.nonce().size() != 16)                          return false;
    auto pubkey = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(c.pubkey().data()),
        c.pubkey().size());
    auto nonce = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(c.nonce().data()),
        c.nonce().size());
    auto signing_bytes = canonical_signing_bytes(
        c.username(), pubkey, c.timestamp_ms(), nonce);
    return 0 == crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char*>(c.signature().data()),
        signing_bytes.data(), signing_bytes.size(),
        pubkey.data());
}

constexpr const char* kSchema = R"sql(
CREATE TABLE IF NOT EXISTS username_claims (
    username     TEXT NOT NULL,
    pubkey       BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    nonce        BLOB NOT NULL,
    signature    BLOB NOT NULL,
    PRIMARY KEY (username, pubkey)
);
CREATE INDEX IF NOT EXISTS idx_username_claims_pubkey
    ON username_claims(pubkey);
CREATE INDEX IF NOT EXISTS idx_username_claims_ts
    ON username_claims(timestamp_ms);
)sql";

void throw_sql(const char* ctx, sqlite3* db) {
    throw std::runtime_error(std::string("UsernameLog: ") + ctx + ": " +
        (db ? sqlite3_errmsg(db) : "no db"));
}

}  // namespace

struct UsernameLog::Impl {
    sqlite3* db = nullptr;
    bool owns_db = false;

    ~Impl() {
        if (owns_db && db) sqlite3_close(db);
    }
};

UsernameLog::UsernameLog(fb::store::SqliteStore& /*store*/) {
    // The header signature accepts an SqliteStore so callers can pass the
    // existing app DB if they want. v0 keeps the schema separate (own
    // file) — simpler ownership, no conflict with the user-vault
    // encryption wrapping. The store argument is reserved for future
    // refactors that may merge schemas.
    (void)0;
    impl_ = std::make_unique<Impl>();
    if (sqlite3_open(":memory:", &impl_->db) != SQLITE_OK) {
        throw_sql("open in-memory", impl_->db);
    }
    impl_->owns_db = true;
    char* err = nullptr;
    if (sqlite3_exec(impl_->db, kSchema, nullptr, nullptr, &err)
        != SQLITE_OK) {
        const std::string msg = err ? err : "unknown";
        sqlite3_free(err);
        throw std::runtime_error("UsernameLog: schema: " + msg);
    }
}

UsernameLog::~UsernameLog() = default;

UsernameLog::AppendResult UsernameLog::append_claim(
    const fb::proto::UserClaim& claim,
    std::uint64_t now_ms) {
    // 1. Format checks.
    if (!is_valid_username(claim.username()))           return AppendResult::kRejectedFormat;
    if (claim.pubkey().size() != crypto_sign_PUBLICKEYBYTES)
                                                          return AppendResult::kRejectedFormat;
    if (claim.nonce().size() != 16)                     return AppendResult::kRejectedFormat;
    if (claim.signature().size() != crypto_sign_BYTES)  return AppendResult::kRejectedFormat;

    // 2. Clock skew.
    if (now_ms == 0) {
        now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }
    if (claim.timestamp_ms() > now_ms + kAcceptedClockSkewMs) {
        return AppendResult::kRejectedClock;
    }

    // 3. Signature.
    if (!verify_claim_signature(claim)) return AppendResult::kRejectedSig;

    // 4. Idempotency check on (username, pubkey) primary key.
    {
        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(impl_->db,
                "SELECT 1 FROM username_claims "
                "WHERE username = ? AND pubkey = ?;",
                -1, &sel, nullptr) != SQLITE_OK) {
            throw_sql("prepare idempotent-check", impl_->db);
        }
        sqlite3_bind_text(sel, 1, claim.username().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(sel, 2, claim.pubkey().data(),
                          static_cast<int>(claim.pubkey().size()),
                          SQLITE_TRANSIENT);
        const bool exists = sqlite3_step(sel) == SQLITE_ROW;
        sqlite3_finalize(sel);
        if (exists) return AppendResult::kAlreadyKnown;
    }

    // 5. Insert. Different (username, pubkey) pairs always coexist —
    // resolve() figures out who actually owns the name.
    sqlite3_stmt* ins = nullptr;
    if (sqlite3_prepare_v2(impl_->db,
            "INSERT INTO username_claims "
            "(username, pubkey, timestamp_ms, nonce, signature) "
            "VALUES (?, ?, ?, ?, ?);",
            -1, &ins, nullptr) != SQLITE_OK) {
        throw_sql("prepare insert", impl_->db);
    }
    sqlite3_bind_text(ins, 1, claim.username().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(ins, 2, claim.pubkey().data(),
                      static_cast<int>(claim.pubkey().size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 3, static_cast<sqlite3_int64>(claim.timestamp_ms()));
    sqlite3_bind_blob(ins, 4, claim.nonce().data(),
                      static_cast<int>(claim.nonce().size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(ins, 5, claim.signature().data(),
                      static_cast<int>(claim.signature().size()),
                      SQLITE_TRANSIENT);
    const int rc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE) {
        throw_sql("insert", impl_->db);
    }
    return AppendResult::kAccepted;
}

std::optional<std::array<std::uint8_t, 32>> UsernameLog::resolve(
    std::string_view username) const {
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(impl_->db,
            "SELECT pubkey FROM username_claims "
            "WHERE username = ? "
            "ORDER BY timestamp_ms ASC, hex(signature) ASC LIMIT 1;",
            -1, &sel, nullptr) != SQLITE_OK) {
        throw_sql("prepare resolve", impl_->db);
    }
    sqlite3_bind_text(sel, 1, std::string(username).c_str(), -1,
                      SQLITE_TRANSIENT);
    std::optional<std::array<std::uint8_t, 32>> out;
    if (sqlite3_step(sel) == SQLITE_ROW) {
        const auto* p = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(sel, 0));
        const int n = sqlite3_column_bytes(sel, 0);
        if (n == 32) {
            std::array<std::uint8_t, 32> arr{};
            std::memcpy(arr.data(), p, 32);
            out = arr;
        }
    }
    sqlite3_finalize(sel);
    return out;
}

std::vector<std::string> UsernameLog::usernames_of(
    std::span<const std::uint8_t> pubkey) const {
    std::vector<std::string> out;
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(impl_->db,
            "SELECT username FROM username_claims "
            "WHERE pubkey = ? ORDER BY timestamp_ms ASC;",
            -1, &sel, nullptr) != SQLITE_OK) {
        throw_sql("prepare usernames_of", impl_->db);
    }
    sqlite3_bind_blob(sel, 1, pubkey.data(),
                      static_cast<int>(pubkey.size()), SQLITE_TRANSIENT);
    while (sqlite3_step(sel) == SQLITE_ROW) {
        const auto* t = reinterpret_cast<const char*>(
            sqlite3_column_text(sel, 0));
        const int n = sqlite3_column_bytes(sel, 0);
        out.emplace_back(t, t + n);
    }
    sqlite3_finalize(sel);
    return out;
}

std::vector<fb::proto::UserClaim> UsernameLog::claims_since(
    std::uint64_t since_ms, std::size_t max) const {
    std::vector<fb::proto::UserClaim> out;
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(impl_->db,
            "SELECT username, pubkey, timestamp_ms, nonce, signature "
            "FROM username_claims "
            "WHERE timestamp_ms > ? "
            "ORDER BY timestamp_ms ASC LIMIT ?;",
            -1, &sel, nullptr) != SQLITE_OK) {
        throw_sql("prepare claims_since", impl_->db);
    }
    sqlite3_bind_int64(sel, 1, static_cast<sqlite3_int64>(since_ms));
    sqlite3_bind_int64(sel, 2, static_cast<sqlite3_int64>(max));
    while (sqlite3_step(sel) == SQLITE_ROW) {
        fb::proto::UserClaim c;
        const auto* uname = reinterpret_cast<const char*>(
            sqlite3_column_text(sel, 0));
        c.set_username(std::string(uname,
            uname + sqlite3_column_bytes(sel, 0)));
        const auto* pub = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(sel, 1));
        c.set_pubkey(std::string(pub,
            pub + sqlite3_column_bytes(sel, 1)));
        c.set_timestamp_ms(static_cast<std::uint64_t>(
            sqlite3_column_int64(sel, 2)));
        const auto* nonce = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(sel, 3));
        c.set_nonce(std::string(nonce,
            nonce + sqlite3_column_bytes(sel, 3)));
        const auto* sig = static_cast<const std::uint8_t*>(
            sqlite3_column_blob(sel, 4));
        c.set_signature(std::string(sig,
            sig + sqlite3_column_bytes(sel, 4)));
        out.push_back(std::move(c));
    }
    sqlite3_finalize(sel);
    return out;
}

std::size_t UsernameLog::total_claims() const {
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(impl_->db,
            "SELECT COUNT(*) FROM username_claims;",
            -1, &sel, nullptr) != SQLITE_OK) {
        throw_sql("prepare total_claims", impl_->db);
    }
    std::size_t n = 0;
    if (sqlite3_step(sel) == SQLITE_ROW) {
        n = static_cast<std::size_t>(sqlite3_column_int64(sel, 0));
    }
    sqlite3_finalize(sel);
    return n;
}

}  // namespace fb::identity
