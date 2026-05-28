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

// Dual (duress) vault format: two concatenated v2 blobs back-to-back, 210
// bytes total. No magic byte — to a forensic analyst the file just looks
// like two adjacent blobs (or one valid + 105 bytes of "padding"). See
// open_seed_dual / seal_seed_dual below.
inline constexpr std::size_t kVaultDualBytes = 2 * kVaultBlobBytes;   // 210

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

// ---- Duress vault ---------------------------------------------------------
//
// Two seeds, two passphrases, one file. The same physical bytes decrypt to
// EITHER the real identity (under the real passphrase) or a decoy identity
// (under the duress passphrase). An adversary coercing a passphrase cannot
// tell which they were given — both succeed equally, and the file looks
// identical either way. Defense against border coercion / shoulder-surfing
// / forced-unlock scenarios.
//
// Format: real_blob (105) || decoy_blob (105) — two independent v2 blobs
// concatenated. Each is encrypted with its own salt + nonce + Argon2id
// derivation; without the matching passphrase, neither half decapsulates.
// Forensic indistinguishability from a "corrupted" single-blob file: a
// passive analyst sees the first 105 bytes are a valid v2 blob and the
// rest looks like high-entropy garbage (which, without the decoy
// passphrase, it is).
//
// SECURITY NOTE: an analyst with knowledge of THIS format can tell a dual
// from a single by file size (210 vs 105). The deniability against a
// state-of-the-art-aware adversary is therefore reduced to "I don't have
// a decoy passphrase set". Users who need stronger deniability should
// store the vault file with mtime jitter and avoid keeping the desktop
// install in a forensically-discoverable location.
[[nodiscard]] VaultBlob seal_seed_dual(const QString& real_passphrase,
                                       const Seed&    real_seed,
                                       const QString& decoy_passphrase,
                                       const Seed&    decoy_seed,
                                       std::uint64_t  opslimit = 0,
                                       std::uint64_t  memlimit = 0);

// Try `passphrase` against both halves of a dual blob. Returns whichever
// seed decapsulates, or std::nullopt if neither did (wrong passphrase /
// tampered file). The CALLER cannot tell which half succeeded — and
// neither can an observer who sees only the input bytes + return value.
//
// Also works on a single-blob file (105 bytes): falls back to plain
// open_seed. This lets one CLI hook accept either format.
[[nodiscard]] std::optional<Seed> open_seed_dual(const QString& passphrase,
                                                  const VaultBlob& blob);

// ---- Multi-persona vault (N personas, one file) ---------------------------
//
// Generalizes the dual API to N personas. The vault file is N concatenated
// v2 blobs, one per persona, each with its own passphrase + seed. Use cases:
//   * Work persona / personal persona / activist persona on one device
//     with no cross-linkage at the wire protocol — different identities
//     mean different pubkeys, different prekey bundles, different
//     ratchets, different gossip beacons.
//   * Per-context burner identities for time-bounded conversations.
//
// Forensic note: the file size leaks N (it's N * 105 bytes). An adversary
// with format awareness can count personas; what they cannot do is enumerate
// them without each passphrase. For stronger size-hiding, pad the file with
// extra "decoy" persona slots (the same as seal_seed_dual achieves with
// N=2 for the simplest coercion-defense case).
//
// passphrases.size() MUST equal seeds.size() and be >= 1.
[[nodiscard]] VaultBlob seal_seeds_multi(const QStringList& passphrases,
                                          const std::vector<Seed>& seeds,
                                          std::uint64_t opslimit = 0,
                                          std::uint64_t memlimit = 0);

// Try `passphrase` against every slot in the multi-blob. Returns the seed
// of the first slot it opens. Works on dual (N=2), multi (N>2), and single
// (105 bytes — falls back to open_seed). The CALLER cannot tell which slot
// matched — exactly the property we want.
[[nodiscard]] std::optional<Seed> open_seed_multi(const QString& passphrase,
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
