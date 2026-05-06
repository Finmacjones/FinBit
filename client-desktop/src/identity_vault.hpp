// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Desktop identity vault.
//
// Stores a 32-byte Ed25519 seed at rest, sealed with Argon2id-derived key +
// XChaCha20-Poly1305. The on-disk blob format is byte-identical to the web
// client's seal_seed / open_seed (see client-web/wasm-shim/finbit_wasm.cpp),
// so a recovery code or an exported vault file can move freely between web
// and desktop.
//
// Format v2 (105 bytes total):
//   [version=2 (1)][salt(16)][opslimit(u64 BE)][memlimit(u64 BE)]
//     [nonce(24)][ct+tag(48)]
// AAD = first 33 bytes (version || salt || ops || mem). Binding KDF
// params into AAD prevents a write-capable attacker from downgrading work
// factor without invalidating the AEAD tag.
//
// Format v1 (104 bytes): same layout minus the version byte; readable by
// open_seed for backwards compat, never written.
//
// Files live under QStandardPaths::AppLocalDataLocation/<username>.vault.

#include <QDir>
#include <QString>
#include <QStringList>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace fb::desktop {

inline constexpr std::size_t kVaultV1Bytes   = 104;
inline constexpr std::size_t kVaultBlobBytes = 105;   // v2: 1 + v1
inline constexpr std::uint8_t kVaultVersion  = 2;
inline constexpr std::size_t kSeedBytes      = 32;

using Seed       = std::array<std::uint8_t, kSeedBytes>;
using VaultBlob  = std::vector<std::uint8_t>;

// Encrypt the seed with a fresh salt + nonce. Uses Argon2id INTERACTIVE
// (~64 MiB / ~0.5 s) tier by default; pass non-zero overrides for tests.
//
// Throws std::runtime_error on KDF failure (libsodium OOM) or empty
// passphrase. NEVER throws on a "wrong passphrase" — that's an open_vault
// concern.
[[nodiscard]] VaultBlob seal_seed(const QString& passphrase, const Seed& seed,
                                  std::uint64_t opslimit = 0,
                                  std::uint64_t memlimit = 0);

// Decrypt. Returns std::nullopt on wrong passphrase / tampered blob /
// truncated blob / blob whose memlimit doesn't fit a size_t on this build.
[[nodiscard]] std::optional<Seed> open_seed(const QString& passphrase,
                                            const VaultBlob& blob);

// Filesystem helpers --------------------------------------------------------

// Default vault directory: QStandardPaths::AppLocalDataLocation. Created
// on demand with 0700 perms (best effort — Qt can only honour mkpath).
[[nodiscard]] QDir vault_dir();

// Full path for `<username>.vault` under vault_dir().
[[nodiscard]] QString vault_path_for(const QString& username);

// List usernames whose vault file exists in `vault_dir()`.
[[nodiscard]] QStringList list_vault_usernames();

// Read the raw vault blob from a path (or std::nullopt if missing /
// wrong size). Doesn't decrypt — caller passes the result to open_seed.
[[nodiscard]] std::optional<VaultBlob> load_vault_file(const QString& path);

// Atomic-ish write: writes to `path + ".tmp"` with 0600 perms then
// renames. Throws std::runtime_error on I/O failure.
void save_vault_file(const QString& path, const VaultBlob& blob);

void remove_vault_file(const QString& path);

// Recovery code helpers (64-char lowercase hex of the seed). Same format
// the web client emits — paste-portable.
[[nodiscard]] QString seed_to_recovery_hex(const Seed& seed);
[[nodiscard]] std::optional<Seed> recovery_hex_to_seed(const QString& hex);

}  // namespace fb::desktop
