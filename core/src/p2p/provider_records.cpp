// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/provider_records.hpp"

#include <sodium.h>

#include "dht.pb.h"

#include <chrono>
#include <cstring>
#include <map>
#include <stdexcept>
#include <vector>

namespace fb::p2p {

// ---------------------------------------------------------------------------
// Canonical signing bytes layout. Fixed magic + version makes future
// schema changes (e.g. adding capability flags) introduce a new magic
// rather than ambiguity.
//
//   "fb.p2p.ProviderRecord:v1\n"
//   uint8(pubkey_len = 32) || pubkey
//   uint16_be(addr_count)
//   for each address:
//       uint16_be(addr_len) || addr_bytes
//   uint64_be(published_at_ms)
//   uint64_be(ttl_ms)
//   uint8(nonce_len = 16) || nonce
// ---------------------------------------------------------------------------
namespace {

constexpr const char* kCanonicalMagic = "fb.p2p.ProviderRecord:v1\n";

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
    std::span<const std::uint8_t> publisher_pubkey,
    const std::vector<std::string>& addresses,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms,
    std::span<const std::uint8_t> nonce) {
    if (publisher_pubkey.size() != 32) {
        throw std::invalid_argument(
            "ProviderRecord: publisher_pubkey must be 32 bytes (Ed25519)");
    }
    if (nonce.size() != 16) {
        throw std::invalid_argument(
            "ProviderRecord: nonce must be 16 bytes");
    }
    if (addresses.size() > kMaxAddressesPerRecord) {
        throw std::invalid_argument(
            "ProviderRecord: too many addresses (max " +
            std::to_string(kMaxAddressesPerRecord) + ")");
    }
    std::vector<std::uint8_t> out;
    const std::string magic = kCanonicalMagic;
    out.insert(out.end(), magic.begin(), magic.end());
    out.push_back(32);
    out.insert(out.end(), publisher_pubkey.begin(), publisher_pubkey.end());
    append_be16(out, static_cast<std::uint16_t>(addresses.size()));
    for (const auto& addr : addresses) {
        if (addr.size() > kMaxAddressBytes) {
            throw std::invalid_argument(
                "ProviderRecord: address exceeds " +
                std::to_string(kMaxAddressBytes) + " bytes");
        }
        append_be16(out, static_cast<std::uint16_t>(addr.size()));
        out.insert(out.end(), addr.begin(), addr.end());
    }
    append_be64(out, published_at_ms);
    append_be64(out, ttl_ms);
    out.push_back(16);
    out.insert(out.end(), nonce.begin(), nonce.end());
    return out;
}

fb::proto::ProviderRecord build_record(
    std::span<const std::uint8_t> sig_pub,
    std::span<const std::uint8_t> sig_priv,
    const std::vector<std::string>& addresses,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms) {
    if (sig_pub.size() != crypto_sign_PUBLICKEYBYTES) {
        throw std::invalid_argument(
            "build_record: sig_pub must be 32 bytes");
    }
    if (sig_priv.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::invalid_argument(
            "build_record: sig_priv must be 64 bytes");
    }
    if (addresses.empty()) {
        throw std::invalid_argument(
            "build_record: address list cannot be empty (a record with "
            "no reachable addresses is meaningless)");
    }
    fb::proto::ProviderRecord out;
    out.set_publisher_pubkey(std::string(sig_pub.begin(), sig_pub.end()));
    for (const auto& a : addresses) out.add_addresses(a);
    out.set_published_at_ms(published_at_ms);
    out.set_ttl_ms(ttl_ms);

    std::array<std::uint8_t, 16> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    out.set_nonce(std::string(nonce.begin(), nonce.end()));

    auto signing_bytes = canonical_signing_bytes(
        sig_pub, addresses, published_at_ms, ttl_ms,
        std::span<const std::uint8_t>(nonce.data(), nonce.size()));
    std::array<std::uint8_t, crypto_sign_BYTES> sig{};
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              signing_bytes.data(), signing_bytes.size(),
                              sig_priv.data()) != 0) {
        throw std::runtime_error(
            "build_record: crypto_sign_detached failed");
    }
    out.set_signature(std::string(sig.begin(), sig.begin() + sig_len));
    return out;
}

namespace {

bool verify_record_signature(const fb::proto::ProviderRecord& r) {
    if (r.publisher_pubkey().size() != crypto_sign_PUBLICKEYBYTES) return false;
    if (r.signature().size() != crypto_sign_BYTES)                  return false;
    if (r.nonce().size() != 16)                                     return false;
    if (r.addresses().size() == 0)                                   return false;
    if (static_cast<std::size_t>(r.addresses().size())
        > kMaxAddressesPerRecord)                                   return false;
    std::vector<std::string> addrs;
    addrs.reserve(static_cast<std::size_t>(r.addresses().size()));
    for (const auto& a : r.addresses()) {
        if (a.size() > kMaxAddressBytes) return false;
        addrs.push_back(a);
    }
    auto pub = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.publisher_pubkey().data()),
        r.publisher_pubkey().size());
    auto nonce = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.nonce().data()),
        r.nonce().size());
    auto signing_bytes = canonical_signing_bytes(
        pub, addrs, r.published_at_ms(), r.ttl_ms(), nonce);
    return 0 == crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char*>(r.signature().data()),
        signing_bytes.data(), signing_bytes.size(),
        pub.data());
}

bool record_expired(const fb::proto::ProviderRecord& r,
                     std::uint64_t now_ms) {
    return r.published_at_ms() + r.ttl_ms() <= now_ms;
}

std::uint64_t now_ms_or(std::uint64_t override_ms) {
    if (override_ms != 0) return override_ms;
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// Make a stable map-key from publisher pubkey bytes. Returns a string
// view because std::array isn't trivially hashable; std::string is the
// pragmatic compromise (treated as an opaque byte container).
std::string pubkey_key(std::span<const std::uint8_t> pubkey) {
    return std::string(reinterpret_cast<const char*>(pubkey.data()),
                        pubkey.size());
}

// Per-record idempotency key: pubkey || nonce. Two records with the
// same pubkey but different nonces are different (multi-homed peer
// re-publishing).
std::string record_key(const fb::proto::ProviderRecord& r) {
    std::string out;
    out.reserve(r.publisher_pubkey().size() + r.nonce().size());
    out.append(r.publisher_pubkey());
    out.append(r.nonce());
    return out;
}

}  // namespace

struct ProviderStore::Impl {
    // Outer key: publisher pubkey bytes. Inner key: record_key (pubkey ||
    // nonce). Two layers so get() is O(records-for-this-publisher) and
    // dedupe is O(1).
    std::map<std::string,
             std::map<std::string, fb::proto::ProviderRecord>> by_publisher;
};

ProviderStore::ProviderStore() : impl_(std::make_unique<Impl>()) {}
ProviderStore::~ProviderStore() = default;

ProviderStore::PutResult ProviderStore::put(
    const fb::proto::ProviderRecord& record,
    std::uint64_t now_ms) {
    // Format checks first (cheaper than signature verify).
    if (record.publisher_pubkey().size() != crypto_sign_PUBLICKEYBYTES)
        return PutResult::kRejectedFormat;
    if (record.signature().size() != crypto_sign_BYTES)
        return PutResult::kRejectedFormat;
    if (record.nonce().size() != 16)
        return PutResult::kRejectedFormat;
    if (record.addresses().size() == 0)
        return PutResult::kRejectedFormat;
    if (static_cast<std::size_t>(record.addresses().size())
        > kMaxAddressesPerRecord)
        return PutResult::kRejectedFormat;
    for (const auto& a : record.addresses()) {
        if (a.size() > kMaxAddressBytes) return PutResult::kRejectedFormat;
    }

    const auto now = now_ms_or(now_ms);
    if (record.published_at_ms() > now + kRecordClockSkewMs)
        return PutResult::kRejectedClock;
    if (record_expired(record, now))
        return PutResult::kRejectedExpired;

    if (!verify_record_signature(record))
        return PutResult::kRejectedSig;

    auto pkey = pubkey_key(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(record.publisher_pubkey().data()),
        record.publisher_pubkey().size()));
    auto rkey = record_key(record);
    auto& bucket = impl_->by_publisher[pkey];
    auto [it, inserted] = bucket.try_emplace(rkey, record);
    return inserted ? PutResult::kAccepted : PutResult::kAlreadyKnown;
}

std::vector<fb::proto::ProviderRecord> ProviderStore::get(
    std::span<const std::uint8_t> publisher_pubkey,
    std::uint64_t now_ms) const {
    const auto now = now_ms_or(now_ms);
    std::vector<fb::proto::ProviderRecord> out;
    auto pkey = pubkey_key(publisher_pubkey);
    auto it = impl_->by_publisher.find(pkey);
    if (it == impl_->by_publisher.end()) return out;
    for (const auto& [_rk, rec] : it->second) {
        if (!record_expired(rec, now)) out.push_back(rec);
    }
    return out;
}

std::size_t ProviderStore::prune_expired(std::uint64_t now_ms) {
    const auto now = now_ms_or(now_ms);
    std::size_t pruned = 0;
    for (auto pit = impl_->by_publisher.begin();
         pit != impl_->by_publisher.end();) {
        auto& bucket = pit->second;
        for (auto rit = bucket.begin(); rit != bucket.end();) {
            if (record_expired(rit->second, now)) {
                rit = bucket.erase(rit);
                ++pruned;
            } else {
                ++rit;
            }
        }
        if (bucket.empty()) {
            pit = impl_->by_publisher.erase(pit);
        } else {
            ++pit;
        }
    }
    return pruned;
}

std::size_t ProviderStore::size() const {
    std::size_t n = 0;
    for (const auto& [_pk, bucket] : impl_->by_publisher) {
        n += bucket.size();
    }
    return n;
}

}  // namespace fb::p2p
