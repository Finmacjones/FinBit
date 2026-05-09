// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/offline_relay.hpp"

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <string>

namespace fb::p2p {

namespace {

std::uint64_t now_ms_or(std::uint64_t override_ms) {
    if (override_ms != 0) return override_ms;
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

}  // namespace

struct OfflineRelayStore::Impl {
    struct Blob {
        std::vector<std::uint8_t> bytes;
        std::uint64_t              deposited_at_ms = 0;
    };
    // Per-recipient FIFO (deque) of queued blobs, keyed by raw pubkey
    // bytes (32B Ed25519, but we don't enforce the size here — the
    // public deposit() does the format check).
    std::map<std::string, std::deque<Blob>> by_recipient;
    mutable std::mutex                       mu;
};

OfflineRelayStore::OfflineRelayStore() : impl_(std::make_unique<Impl>()) {}
OfflineRelayStore::~OfflineRelayStore() = default;

OfflineRelayStore::DepositResult OfflineRelayStore::deposit(
    std::span<const std::uint8_t> recipient_pubkey,
    std::span<const std::uint8_t> payload,
    std::uint64_t now_ms) {
    if (recipient_pubkey.size() != 32) return DepositResult::kRejectedFormat;
    if (payload.empty())                return DepositResult::kRejectedFormat;
    const std::string key(recipient_pubkey.begin(), recipient_pubkey.end());
    const auto t = now_ms_or(now_ms);
    std::lock_guard lk(impl_->mu);
    auto& q = impl_->by_recipient[key];
    if (q.size() >= kMaxBlobsPerRecipient) {
        return DepositResult::kRejectedFull;
    }
    q.push_back({std::vector<std::uint8_t>(payload.begin(), payload.end()), t});
    return DepositResult::kAccepted;
}

std::vector<std::vector<std::uint8_t>>
OfflineRelayStore::fetch_and_clear(
    std::span<const std::uint8_t> recipient_pubkey,
    std::uint64_t now_ms) {
    if (recipient_pubkey.size() != 32) return {};
    const std::string key(recipient_pubkey.begin(), recipient_pubkey.end());
    const auto t = now_ms_or(now_ms);
    std::vector<std::vector<std::uint8_t>> out;
    std::lock_guard lk(impl_->mu);
    auto it = impl_->by_recipient.find(key);
    if (it == impl_->by_recipient.end()) return out;
    for (auto& b : it->second) {
        if (b.deposited_at_ms + kDefaultBlobTtlMs > t) {
            out.push_back(std::move(b.bytes));
        }
        // Expired blobs are simply skipped — we erase the whole
        // bucket below regardless.
    }
    impl_->by_recipient.erase(it);
    return out;
}

std::size_t OfflineRelayStore::prune_expired(
    std::uint64_t now_ms, std::uint64_t ttl_ms) {
    const auto t = now_ms_or(now_ms);
    std::size_t pruned = 0;
    std::lock_guard lk(impl_->mu);
    for (auto bit = impl_->by_recipient.begin();
         bit != impl_->by_recipient.end();) {
        auto& q = bit->second;
        for (auto qit = q.begin(); qit != q.end();) {
            if (qit->deposited_at_ms + ttl_ms <= t) {
                qit = q.erase(qit);
                ++pruned;
            } else {
                ++qit;
            }
        }
        if (q.empty()) bit = impl_->by_recipient.erase(bit);
        else ++bit;
    }
    return pruned;
}

std::size_t OfflineRelayStore::total_blobs() const {
    std::lock_guard lk(impl_->mu);
    std::size_t n = 0;
    for (const auto& [_k, q] : impl_->by_recipient) n += q.size();
    return n;
}

std::size_t OfflineRelayStore::recipients() const {
    std::lock_guard lk(impl_->mu);
    return impl_->by_recipient.size();
}

}  // namespace fb::p2p
