// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Connection book + offline queue. The relay holds a Connection per active
// socket, tracking which user it represents. When an Envelope arrives, the
// relay looks up the recipient's Connection (if online) and writes the frame;
// otherwise it queues the envelope for later delivery.

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "fb/store/sqlite_store.hpp"

namespace fb::server {

class Relay {
public:
    // If `db_path` is non-empty, the offline message queue is persisted to
    // SQLite — survives a server restart. Otherwise we fall back to the
    // in-memory queue (Phase 0 behaviour).
    void enable_persistent_offline(const std::string& db_path);

    // Borrow the same SQLite store the offline queue uses (so the directory
    // can persist user registrations + prekey bundles in the same DB).
    [[nodiscard]] fb::store::SqliteStore* persistent_store() noexcept {
        return persistent_.get();
    }

    // Register that fd is the connection for `user_pubkey`. Replaces any
    // prior registration (the older connection is treated as stale).
    void bind(int fd, std::span<const std::uint8_t> user_pubkey);

    // Forget about a connection on disconnect.
    void unbind(int fd);

    // Look up the active fd for a user, if any.
    [[nodiscard]] int lookup(std::span<const std::uint8_t> user_pubkey) const;

    // Queue an envelope blob for a user that isn't currently online. The
    // queue is per-user, FIFO, capped at kMaxQueued entries.
    void enqueue_offline(std::span<const std::uint8_t> user_pubkey,
                         std::vector<std::uint8_t> envelope_bytes);

    // Pop pending envelopes for a user (called when they reconnect).
    [[nodiscard]] std::deque<std::vector<std::uint8_t>> drain_offline(
        std::span<const std::uint8_t> user_pubkey);

    // ---- channel routing ---------------------------------------------------
    void channel_subscribe(int fd, std::span<const std::uint8_t> group_id);
    void channel_unsubscribe(int fd, std::span<const std::uint8_t> group_id);
    [[nodiscard]] std::vector<int> channel_subscribers(
        std::span<const std::uint8_t> group_id) const;
    void unbind_all_channels(int fd);

    static constexpr std::size_t kMaxQueued = 1024;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, int> user_to_fd_;
    std::unordered_map<int, std::string> fd_to_user_;
    std::unordered_map<std::string, std::deque<std::vector<std::uint8_t>>> offline_;
    // group_id -> set of subscribed fds
    std::unordered_map<std::string, std::vector<int>> chan_subs_;
    // fd -> set of group_ids it's subscribed to (for cleanup on disconnect)
    std::unordered_map<int, std::vector<std::string>> fd_to_chans_;
    // Optional persistent offline-message store (Phase 1). Promoted from the
    // RAM-only deque when enable_persistent_offline() is called at startup.
    std::unique_ptr<fb::store::SqliteStore> persistent_;
};

}  // namespace fb::server
