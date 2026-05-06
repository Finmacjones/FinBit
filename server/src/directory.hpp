// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// In-memory directory of known users + their published prekey bundles.
// SQLite-persisted in production; Phase 0 keeps it RAM-only with a TODO.

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "fb/store/sqlite_store.hpp"

namespace fb::server {

class Directory {
public:
    // Optional persistence: if set, every register_user / put_bundle is
    // mirrored to SQLite, and the in-memory caches are seeded from it on
    // first lookup that misses.
    void enable_persistence(fb::store::SqliteStore* store) noexcept { store_ = store; }

    // Returns true if the username was newly registered, false if it was
    // already taken (by a different pubkey).
    bool register_user(const std::string& username, std::span<const std::uint8_t> pubkey);

    // Replace the prekey bundle for a user.
    void put_bundle(const std::string& username, std::span<const std::uint8_t> bundle_blob);

    // Fetch the most recent bundle for a user, if any.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_bundle(
        const std::string& username) const;

    // Look up the identity pubkey associated with a username.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> resolve(
        const std::string& username) const;

    // Reverse: pubkey → username. Slow path (linear scan); fine for the
    // Phase-1 demo. Production would index this.
    [[nodiscard]] std::optional<std::string> reverse_resolve(
        std::span<const std::uint8_t> pubkey) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::vector<std::uint8_t>> name_to_pub_;
    std::unordered_map<std::string, std::vector<std::uint8_t>> name_to_bundle_;
    fb::store::SqliteStore* store_ = nullptr;  // non-owning
};

}  // namespace fb::server
