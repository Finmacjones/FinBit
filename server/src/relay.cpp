// SPDX-License-Identifier: AGPL-3.0-or-later
#include "relay.hpp"

#include <algorithm>
#include <chrono>

namespace fb::server {

void Relay::enable_persistent_offline(const std::string& db_path) {
    std::lock_guard lk(mu_);
    persistent_ = fb::store::SqliteStore::open(db_path);
}

void Relay::bind(int fd, std::span<const std::uint8_t> user_pubkey) {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(user_pubkey.data()), user_pubkey.size());
    // Evict any prior fd for this user.
    auto it = user_to_fd_.find(key);
    if (it != user_to_fd_.end()) {
        fd_to_user_.erase(it->second);
    }
    user_to_fd_[key] = fd;
    fd_to_user_[fd] = key;
}

void Relay::unbind(int fd) {
    std::lock_guard lk(mu_);
    auto it = fd_to_user_.find(fd);
    if (it == fd_to_user_.end()) return;
    auto u = user_to_fd_.find(it->second);
    if (u != user_to_fd_.end() && u->second == fd) {
        user_to_fd_.erase(u);
    }
    fd_to_user_.erase(it);
}

int Relay::lookup(std::span<const std::uint8_t> user_pubkey) const {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(user_pubkey.data()), user_pubkey.size());
    auto it = user_to_fd_.find(key);
    return (it == user_to_fd_.end()) ? -1 : it->second;
}

void Relay::enqueue_offline(std::span<const std::uint8_t> user_pubkey,
                            std::vector<std::uint8_t> envelope_bytes) {
    std::lock_guard lk(mu_);
    if (persistent_) {
        const auto now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        persistent_->srv_offline_enqueue(
            user_pubkey,
            std::span<const std::uint8_t>(envelope_bytes.data(), envelope_bytes.size()),
            now_ms);
        return;
    }
    std::string key(reinterpret_cast<const char*>(user_pubkey.data()), user_pubkey.size());
    auto& q = offline_[key];
    if (q.size() >= kMaxQueued) {
        q.pop_front();  // drop oldest
    }
    q.push_back(std::move(envelope_bytes));
}

std::deque<std::vector<std::uint8_t>> Relay::drain_offline(
    std::span<const std::uint8_t> user_pubkey) {
    std::lock_guard lk(mu_);
    if (persistent_) {
        auto rows = persistent_->srv_offline_drain(user_pubkey);
        std::deque<std::vector<std::uint8_t>> out;
        for (auto& r : rows) out.push_back(std::move(r));
        return out;
    }
    std::string key(reinterpret_cast<const char*>(user_pubkey.data()), user_pubkey.size());
    auto it = offline_.find(key);
    if (it == offline_.end()) return {};
    auto out = std::move(it->second);
    offline_.erase(it);
    return out;
}

void Relay::channel_subscribe(int fd, std::span<const std::uint8_t> group_id) {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(group_id.data()), group_id.size());
    auto& subs = chan_subs_[key];
    if (std::find(subs.begin(), subs.end(), fd) == subs.end()) {
        subs.push_back(fd);
    }
    auto& chans = fd_to_chans_[fd];
    if (std::find(chans.begin(), chans.end(), key) == chans.end()) {
        chans.push_back(key);
    }
}

void Relay::channel_unsubscribe(int fd, std::span<const std::uint8_t> group_id) {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(group_id.data()), group_id.size());
    auto it = chan_subs_.find(key);
    if (it != chan_subs_.end()) {
        auto& v = it->second;
        v.erase(std::remove(v.begin(), v.end(), fd), v.end());
        if (v.empty()) chan_subs_.erase(it);
    }
    auto cit = fd_to_chans_.find(fd);
    if (cit != fd_to_chans_.end()) {
        auto& v = cit->second;
        v.erase(std::remove(v.begin(), v.end(), key), v.end());
        if (v.empty()) fd_to_chans_.erase(cit);
    }
}

std::vector<int> Relay::channel_subscribers(std::span<const std::uint8_t> group_id) const {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(group_id.data()), group_id.size());
    auto it = chan_subs_.find(key);
    if (it == chan_subs_.end()) return {};
    return it->second;
}

void Relay::unbind_all_channels(int fd) {
    std::lock_guard lk(mu_);
    auto cit = fd_to_chans_.find(fd);
    if (cit == fd_to_chans_.end()) return;
    for (const auto& key : cit->second) {
        auto sit = chan_subs_.find(key);
        if (sit != chan_subs_.end()) {
            auto& v = sit->second;
            v.erase(std::remove(v.begin(), v.end(), fd), v.end());
            if (v.empty()) chan_subs_.erase(sit);
        }
    }
    fd_to_chans_.erase(cit);
}

void Relay::room_join(int fd, std::span<const std::uint8_t> room_id) {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(room_id.data()), room_id.size());
    auto& members = room_members_[key];
    if (std::find(members.begin(), members.end(), fd) == members.end()) {
        members.push_back(fd);
    }
    auto& rooms = fd_to_rooms_[fd];
    if (std::find(rooms.begin(), rooms.end(), key) == rooms.end()) {
        rooms.push_back(key);
    }
}

void Relay::room_leave(int fd, std::span<const std::uint8_t> room_id) {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(room_id.data()), room_id.size());
    auto it = room_members_.find(key);
    if (it != room_members_.end()) {
        auto& v = it->second;
        v.erase(std::remove(v.begin(), v.end(), fd), v.end());
        if (v.empty()) room_members_.erase(it);
    }
    auto rit = fd_to_rooms_.find(fd);
    if (rit != fd_to_rooms_.end()) {
        auto& v = rit->second;
        v.erase(std::remove(v.begin(), v.end(), key), v.end());
        if (v.empty()) fd_to_rooms_.erase(rit);
    }
}

std::vector<int> Relay::room_member_fds(std::span<const std::uint8_t> room_id) const {
    std::lock_guard lk(mu_);
    std::string key(reinterpret_cast<const char*>(room_id.data()), room_id.size());
    auto it = room_members_.find(key);
    if (it == room_members_.end()) return {};
    return it->second;
}

std::vector<std::string> Relay::room_member_rooms(int fd) const {
    std::lock_guard lk(mu_);
    auto it = fd_to_rooms_.find(fd);
    if (it == fd_to_rooms_.end()) return {};
    return it->second;
}

void Relay::unbind_all_rooms(int fd) {
    std::lock_guard lk(mu_);
    auto rit = fd_to_rooms_.find(fd);
    if (rit == fd_to_rooms_.end()) return;
    for (const auto& key : rit->second) {
        auto mit = room_members_.find(key);
        if (mit != room_members_.end()) {
            auto& v = mit->second;
            v.erase(std::remove(v.begin(), v.end(), fd), v.end());
            if (v.empty()) room_members_.erase(mit);
        }
    }
    fd_to_rooms_.erase(rit);
}

}  // namespace fb::server
