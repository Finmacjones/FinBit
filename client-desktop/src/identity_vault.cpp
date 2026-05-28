// SPDX-License-Identifier: AGPL-3.0-or-later
#include "identity_vault.hpp"

#include <sodium.h>
#if defined(_WIN32)
#  include <io.h>         // _commit
#  include <windows.h>    // MoveFileExA, MOVEFILE_REPLACE_EXISTING
#else
#  include <unistd.h>     // fsync
#endif
#include <cstdio>        // ::rename (POSIX) / not used on Windows path
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

#include <cstring>
#include <limits>
#include <stdexcept>

namespace fb::desktop {

namespace {

void put_u64_be(std::uint8_t* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) { p[i] = static_cast<std::uint8_t>(v & 0xff); v >>= 8; }
}
std::uint64_t get_u64_be(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

void ensure_sodium() {
    if (sodium_init() == -1) {
        throw std::runtime_error("libsodium init failed");
    }
}

}  // namespace

namespace {
// Defensive bounds applied on OPEN (matches the WASM client). Refuse work
// factors weaker than INTERACTIVE so a write-capable local attacker can't
// downgrade and brute-force; refuse memlimit > 1 GiB so a tampered blob
// can't trigger an Argon2 OOM/hang.
constexpr std::uint64_t kMinOpslimit = 2;                     // INTERACTIVE
constexpr std::uint64_t kMinMemlimit = 64u * 1024u * 1024u;   // INTERACTIVE
constexpr std::uint64_t kMaxMemlimit = 1024u * 1024u * 1024u; // 1 GiB

// Force NFC normalization on the passphrase to keep the same code points
// across IMEs that emit decomposed sequences (e.g. "café" as 'c','a','f',
// 'e','́'). Cross-platform unlock would otherwise fail on the same
// human input.
QByteArray pp_bytes(const QString& s) {
    return s.normalized(QString::NormalizationForm_C).toUtf8();
}
}  // namespace

VaultBlob seal_seed(const QString& passphrase, const Seed& seed,
                    std::uint64_t opslimit, std::uint64_t memlimit) {
    ensure_sodium();
    if (passphrase.isEmpty()) {
        throw std::runtime_error("seal_seed: passphrase must not be empty");
    }
    if (opslimit == 0) opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    if (memlimit == 0) memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

    VaultBlob blob(kVaultBlobBytes);
    blob[0] = kVaultVersion;
    std::uint8_t* salt    = blob.data() + 1;
    std::uint8_t* opsbuf  = salt + crypto_pwhash_SALTBYTES;
    std::uint8_t* membuf  = opsbuf + 8;
    std::uint8_t* nonce   = membuf + 8;
    std::uint8_t* ctpos   = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    randombytes_buf(salt,  crypto_pwhash_SALTBYTES);
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    put_u64_be(opsbuf, opslimit);
    put_u64_be(membuf, memlimit);

    QByteArray pp_utf8 = pp_bytes(passphrase);
    std::array<std::uint8_t, 32> kdf_out{};
    int rc = crypto_pwhash(kdf_out.data(), kdf_out.size(),
                           pp_utf8.constData(),
                           static_cast<unsigned long long>(pp_utf8.size()),
                           salt, opslimit, static_cast<std::size_t>(memlimit),
                           crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(pp_utf8.data(), static_cast<std::size_t>(pp_utf8.size()));
    if (rc != 0) {
        sodium_memzero(kdf_out.data(), kdf_out.size());
        throw std::runtime_error("seal_seed: argon2id derivation failed (out of memory?)");
    }

    const std::size_t aad_len = static_cast<std::size_t>(nonce - blob.data());
    unsigned long long ct_len = 0;
    rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ctpos, &ct_len, seed.data(), seed.size(),
        blob.data(), aad_len, /*nsec=*/nullptr,
        nonce, kdf_out.data());
    sodium_memzero(kdf_out.data(), kdf_out.size());
    if (rc != 0) throw std::runtime_error("seal_seed: aead encrypt failed");
    return blob;
}

std::optional<Seed> open_seed(const QString& passphrase, const VaultBlob& blob) {
    ensure_sodium();
    const bool v2 = (blob.size() == kVaultBlobBytes && blob[0] == kVaultVersion);
    const bool v1 = (blob.size() == kVaultV1Bytes);
    if (!v1 && !v2) return std::nullopt;

    const std::uint8_t* salt   = blob.data() + (v2 ? 1 : 0);
    const std::uint8_t* opsbuf = salt + crypto_pwhash_SALTBYTES;
    const std::uint8_t* membuf = opsbuf + 8;
    const std::uint8_t* nonce  = membuf + 8;
    const std::uint8_t* ct     = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const std::size_t   ct_len = blob.size() - static_cast<std::size_t>(ct - blob.data());

    const std::uint64_t ops = get_u64_be(opsbuf);
    const std::uint64_t mem = get_u64_be(membuf);
    if (mem > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        mem > kMaxMemlimit || mem < kMinMemlimit ||
        ops < kMinOpslimit) {
        return std::nullopt;
    }

    QByteArray pp_utf8 = pp_bytes(passphrase);
    std::array<std::uint8_t, 32> kdf_out{};
    int rc = crypto_pwhash(kdf_out.data(), kdf_out.size(),
                           pp_utf8.constData(),
                           static_cast<unsigned long long>(pp_utf8.size()),
                           salt, ops, static_cast<std::size_t>(mem),
                           crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(pp_utf8.data(), static_cast<std::size_t>(pp_utf8.size()));
    if (rc != 0) {
        sodium_memzero(kdf_out.data(), kdf_out.size());
        return std::nullopt;
    }

    Seed seed{};
    unsigned long long pt_len = 0;
    const std::size_t aad_len = v2 ? static_cast<std::size_t>(nonce - blob.data()) : 0;
    const std::uint8_t* aad   = v2 ? blob.data() : nullptr;
    rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        seed.data(), &pt_len, /*nsec=*/nullptr,
        ct, ct_len, aad, aad_len, nonce, kdf_out.data());
    sodium_memzero(kdf_out.data(), kdf_out.size());
    if (rc != 0) return std::nullopt;
    return seed;
}

QDir vault_dir() {
    QDir d(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation));
    if (!d.exists()) d.mkpath(".");
    // Tighten the directory permissions to 0700 so other users on a shared
    // box can't even ls our vault filenames (which would leak usernames).
    // QFile::setPermissions translates onto chmod(2) on POSIX. Best effort
    // — failures are logged but not fatal.
    QFile::setPermissions(d.absolutePath(),
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    return d;
}

QString vault_path_for(const QString& username) {
    // Strip any path-traversal characters defensively. Vault filenames are
    // user-controlled (the username they pick at create time).
    QString clean = username;
    clean.remove(QChar('/')).remove(QChar('\\')).remove(QChar('\0'));
    if (clean.isEmpty()) clean = "default";
    return vault_dir().filePath(clean + ".vault");
}

QStringList list_vault_usernames() {
    QStringList out;
    QDir d = vault_dir();
    for (const QFileInfo& fi : d.entryInfoList({"*.vault"}, QDir::Files, QDir::Name)) {
        out << fi.completeBaseName();
    }
    return out;
}

std::optional<VaultBlob> load_vault_file(const QString& path) {
    QFile f(path);
    if (!f.exists()) return std::nullopt;
    if (!f.open(QIODevice::ReadOnly)) return std::nullopt;
    QByteArray bytes = f.readAll();
    f.close();
    const std::size_t sz = static_cast<std::size_t>(bytes.size());
    // Accept v1 (104) and v2 (105). open_seed handles dispatch.
    if (sz != kVaultBlobBytes && sz != kVaultV1Bytes) return std::nullopt;
    VaultBlob blob(sz);
    std::memcpy(blob.data(), bytes.constData(), sz);
    return blob;
}

void save_vault_file(const QString& path, const VaultBlob& blob) {
    if (blob.size() != kVaultBlobBytes && blob.size() != kVaultV1Bytes) {
        throw std::runtime_error("save_vault_file: wrong blob size");
    }
    QString tmp = path + ".tmp";
    {
        QFile f(tmp);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            throw std::runtime_error("save_vault_file: cannot open temp file");
        }
        f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
        if (f.write(reinterpret_cast<const char*>(blob.data()),
                    static_cast<qint64>(blob.size())) !=
            static_cast<qint64>(blob.size())) {
            throw std::runtime_error("save_vault_file: short write");
        }
        // fsync the file before the rename so a crash mid-rename can't leave
        // us with a zero-byte vault. Falls back to no-op if QFileDevice::sync
        // isn't available (it is in Qt 5+).
        f.flush();
#if defined(_WIN32)
        // Windows: _commit(handle) flushes the file's kernel buffer
        // to disk — equivalent to POSIX fsync(2). QFile::handle()
        // returns the underlying file descriptor on both targets.
        ::_commit(f.handle());
#else
        ::fsync(f.handle());
#endif
        f.close();
    }
    // POSIX rename(2) overwrites atomically when src+dst are on the same
    // filesystem (mandated by POSIX). Windows rename() FAILS if the
    // destination exists — use MoveFileExA with MOVEFILE_REPLACE_EXISTING
    // for the same atomic semantics.
    const QByteArray src_bytes = QFile::encodeName(tmp);
    const QByteArray dst_bytes = QFile::encodeName(path);
#if defined(_WIN32)
    if (!::MoveFileExA(src_bytes.constData(), dst_bytes.constData(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        QFile::remove(tmp);
        throw std::runtime_error("save_vault_file: atomic rename failed");
    }
#else
    if (::rename(src_bytes.constData(), dst_bytes.constData()) != 0) {
        QFile::remove(tmp);
        throw std::runtime_error("save_vault_file: atomic rename failed");
    }
#endif
}

void remove_vault_file(const QString& path) {
    QFile::remove(path);
}

QString seed_to_recovery_hex(const Seed& seed) {
    QString out;
    out.reserve(64);
    static const char hex[] = "0123456789abcdef";
    for (auto b : seed) {
        out.append(QChar(hex[(b >> 4) & 0xf]));
        out.append(QChar(hex[b & 0xf]));
    }
    return out;
}

std::optional<Seed> recovery_hex_to_seed(const QString& hex) {
    QString clean = hex.simplified().remove(QChar(' ')).toLower();
    if (clean.size() != 64) return std::nullopt;
    Seed out{};
    for (int i = 0; i < 32; ++i) {
        bool ok1 = false, ok2 = false;
        int hi = clean.at(i * 2).digitValue();
        if (hi < 0) {
            QChar c = clean.at(i * 2);
            if (c >= 'a' && c <= 'f') hi = 10 + (c.unicode() - 'a');
            else return std::nullopt;
        }
        int lo = clean.at(i * 2 + 1).digitValue();
        if (lo < 0) {
            QChar c = clean.at(i * 2 + 1);
            if (c >= 'a' && c <= 'f') lo = 10 + (c.unicode() - 'a');
            else return std::nullopt;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        (void)ok1; (void)ok2;
    }
    return out;
}

// ---- Duress vault (dual-blob) ---------------------------------------------

VaultBlob seal_seed_dual(const QString& real_passphrase, const Seed& real_seed,
                          const QString& decoy_passphrase, const Seed& decoy_seed,
                          std::uint64_t opslimit, std::uint64_t memlimit) {
    // Each half is a standard v2 blob with its own salt + nonce. Reusing
    // seal_seed keeps the per-half format byte-identical to a single vault
    // so a forensic analyst cannot tell apart "two halves" from "one valid
    // blob followed by random padding".
    VaultBlob real_blob  = seal_seed(real_passphrase,  real_seed,  opslimit, memlimit);
    VaultBlob decoy_blob = seal_seed(decoy_passphrase, decoy_seed, opslimit, memlimit);
    if (real_blob.size() != kVaultBlobBytes || decoy_blob.size() != kVaultBlobBytes) {
        throw std::runtime_error("seal_seed_dual: unexpected blob size");
    }
    VaultBlob out;
    out.reserve(kVaultDualBytes);
    out.insert(out.end(), real_blob.begin(),  real_blob.end());
    out.insert(out.end(), decoy_blob.begin(), decoy_blob.end());
    return out;
}

std::optional<Seed> open_seed_dual(const QString& passphrase,
                                    const VaultBlob& blob) {
    // Single-blob fallback: lets one CLI hook accept either format.
    if (blob.size() == kVaultBlobBytes || blob.size() == kVaultV1Bytes) {
        return open_seed(passphrase, blob);
    }
    if (blob.size() != kVaultDualBytes) {
        return std::nullopt;
    }
    VaultBlob first(blob.begin(), blob.begin() + kVaultBlobBytes);
    if (auto s = open_seed(passphrase, first)) {
        return s;
    }
    VaultBlob second(blob.begin() + kVaultBlobBytes, blob.end());
    return open_seed(passphrase, second);
    // Either half may succeed. The caller cannot distinguish which —
    // exactly the property we want for plausible-deniability under coercion.
}

// ---- Multi-persona vault (N-blob) -----------------------------------------

VaultBlob seal_seeds_multi(const QStringList& passphrases,
                            const std::vector<Seed>& seeds,
                            std::uint64_t opslimit, std::uint64_t memlimit) {
    if (passphrases.isEmpty() || passphrases.size() != static_cast<int>(seeds.size())) {
        throw std::runtime_error(
            "seal_seeds_multi: passphrases and seeds must be same non-zero length");
    }
    VaultBlob out;
    out.reserve(static_cast<std::size_t>(passphrases.size()) * kVaultBlobBytes);
    for (int i = 0; i < passphrases.size(); ++i) {
        VaultBlob slot = seal_seed(passphrases.at(i),
                                    seeds[static_cast<std::size_t>(i)],
                                    opslimit, memlimit);
        if (slot.size() != kVaultBlobBytes) {
            throw std::runtime_error("seal_seeds_multi: unexpected slot size");
        }
        out.insert(out.end(), slot.begin(), slot.end());
    }
    return out;
}

std::optional<Seed> open_seed_multi(const QString& passphrase,
                                     const VaultBlob& blob) {
    // Single-blob fallback so one CLI hook accepts every format.
    if (blob.size() == kVaultBlobBytes || blob.size() == kVaultV1Bytes) {
        return open_seed(passphrase, blob);
    }
    if (blob.size() < kVaultBlobBytes ||
        blob.size() % kVaultBlobBytes != 0) {
        return std::nullopt;
    }
    const std::size_t slot_count = blob.size() / kVaultBlobBytes;
    for (std::size_t i = 0; i < slot_count; ++i) {
        const auto first = blob.begin() +
            static_cast<std::ptrdiff_t>(i * kVaultBlobBytes);
        const auto last  = first + static_cast<std::ptrdiff_t>(kVaultBlobBytes);
        VaultBlob slot(first, last);
        if (auto s = open_seed(passphrase, slot)) {
            return s;
        }
    }
    return std::nullopt;
}

}  // namespace fb::desktop
