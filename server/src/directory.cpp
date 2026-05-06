// SPDX-License-Identifier: AGPL-3.0-or-later
#include "directory.hpp"

namespace fb::server {

bool Directory::register_user(const std::string& username, std::span<const std::uint8_t> pubkey) {
    std::lock_guard lk(mu_);
    auto it = name_to_pub_.find(username);
    if (it != name_to_pub_.end()) {
        // Already taken; succeed only if same pubkey (idempotent registration).
        return it->second.size() == pubkey.size() &&
               std::equal(it->second.begin(), it->second.end(), pubkey.begin());
    }
    name_to_pub_[username] = std::vector<std::uint8_t>(pubkey.begin(), pubkey.end());
    if (store_) store_->srv_register_user(username, pubkey);
    return true;
}

void Directory::put_bundle(const std::string& key,
                           std::span<const std::uint8_t> bundle_blob) {
    std::lock_guard lk(mu_);
    name_to_bundle_[key] = std::vector<std::uint8_t>(bundle_blob.begin(), bundle_blob.end());
    if (store_) {
        store_->srv_put_prekey_bundle(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(key.data()),
                                           key.size()),
            bundle_blob);
    }
}

std::optional<std::vector<std::uint8_t>> Directory::get_bundle(
    const std::string& key) const {
    std::lock_guard lk(mu_);
    auto it = name_to_bundle_.find(key);
    if (it != name_to_bundle_.end()) return it->second;
    if (store_) {
        // Lazy load from SQLite on first miss.
        auto loaded = store_->srv_get_prekey_bundle(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(key.data()),
                                           key.size()));
        if (loaded) {
            const_cast<Directory*>(this)->name_to_bundle_[key] = *loaded;
            return loaded;
        }
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> Directory::resolve(const std::string& username) const {
    std::lock_guard lk(mu_);
    auto it = name_to_pub_.find(username);
    if (it != name_to_pub_.end()) return it->second;
    if (store_) {
        auto loaded = store_->srv_resolve_username(username);
        if (loaded) {
            const_cast<Directory*>(this)->name_to_pub_[username] = *loaded;
            return loaded;
        }
    }
    return std::nullopt;
}

std::optional<std::string> Directory::reverse_resolve(
    std::span<const std::uint8_t> pubkey) const {
    std::lock_guard lk(mu_);
    for (const auto& [name, p] : name_to_pub_) {
        if (p.size() == pubkey.size() && std::equal(p.begin(), p.end(), pubkey.begin())) {
            return name;
        }
    }
    if (store_) {
        auto loaded = store_->srv_reverse_resolve_pubkey(pubkey);
        if (loaded) {
            const_cast<Directory*>(this)->name_to_pub_[*loaded] =
                std::vector<std::uint8_t>(pubkey.begin(), pubkey.end());
            return loaded;
        }
    }
    return std::nullopt;
}

}  // namespace fb::server
