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
    std::span<const std::uint8_t> nonce,
    const std::vector<std::vector<std::uint8_t>>& offline_relays) {
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
    // I4: offline_relays appended after the nonce. Each entry MUST
    // be exactly 32 bytes (Ed25519 pubkey). Empty list serializes as
    // a single 0 length-prefix so old records (no relays) and new
    // records (relays present) have unambiguous canonical bytes.
    append_be16(out, static_cast<std::uint16_t>(offline_relays.size()));
    for (const auto& r : offline_relays) {
        if (r.size() != 32) {
            throw std::invalid_argument(
                "ProviderRecord: offline_relays entry must be 32B");
        }
        out.insert(out.end(), r.begin(), r.end());
    }
    return out;
}

fb::proto::ProviderRecord build_record(
    std::span<const std::uint8_t> sig_pub,
    std::span<const std::uint8_t> sig_priv,
    const std::vector<std::string>& addresses,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms,
    const std::vector<std::vector<std::uint8_t>>& offline_relays) {
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
    for (const auto& r : offline_relays) {
        if (r.size() != 32) {
            throw std::invalid_argument(
                "build_record: offline_relays entry must be 32B");
        }
        out.add_offline_relays(std::string(r.begin(), r.end()));
    }

    std::array<std::uint8_t, 16> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    out.set_nonce(std::string(nonce.begin(), nonce.end()));

    auto signing_bytes = canonical_signing_bytes(
        sig_pub, addresses, published_at_ms, ttl_ms,
        std::span<const std::uint8_t>(nonce.data(), nonce.size()),
        offline_relays);
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
    std::vector<std::vector<std::uint8_t>> relays;
    relays.reserve(r.offline_relays().size());
    for (const auto& rel : r.offline_relays()) {
        if (rel.size() != 32) return false;
        relays.emplace_back(rel.begin(), rel.end());
    }
    auto signing_bytes = canonical_signing_bytes(
        pub, addrs, r.published_at_ms(), r.ttl_ms(), nonce, relays);
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

// =============================================================================
// PrekeyStore — same building blocks as ProviderStore but with the
// X3DH bundle fields. Layout of the canonical signing bytes:
//
//   "fb.p2p.PrekeyRecord:v1\n"
//   uint8(pubkey_len = 32)              || pubkey
//   uint8(spk_len = 32)                 || signed_prekey
//   uint8(spk_sig_len = 64)             || signed_prekey_signature
//   uint64_be(published_at_ms)
//   uint64_be(ttl_ms)
//   uint8(nonce_len = 16)               || nonce
// =============================================================================

namespace {

constexpr const char* kPrekeyMagic   = "fb.p2p.PrekeyRecord:v1\n";
constexpr const char* kPrekeyMagicV2 = "fb.p2p.PrekeyRecord:v2\n";

// FIPS-203 ML-KEM-768 public key size. Kept local (avoid pulling
// fb/crypto/pq_kem header into p2p just for the constant).
constexpr std::size_t kPqPubBytes = 1184;

}  // namespace

std::vector<std::uint8_t> prekey_canonical_signing_bytes(
    std::span<const std::uint8_t> publisher_pubkey,
    std::span<const std::uint8_t> signed_prekey,
    std::span<const std::uint8_t> signed_prekey_signature,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> pq_pubkey,
    std::span<const std::uint8_t> pq_pubkey_sig) {
    if (publisher_pubkey.size() != 32) {
        throw std::invalid_argument("PrekeyRecord: pubkey must be 32B");
    }
    if (signed_prekey.size() != 32) {
        throw std::invalid_argument(
            "PrekeyRecord: signed_prekey must be 32B (X25519 pub)");
    }
    if (signed_prekey_signature.size() != crypto_sign_BYTES) {
        throw std::invalid_argument(
            "PrekeyRecord: signed_prekey_signature must be 64B");
    }
    if (nonce.size() != 16) {
        throw std::invalid_argument("PrekeyRecord: nonce must be 16B");
    }
    // PQ fields are all-or-nothing.
    const bool pq_present = !pq_pubkey.empty() || !pq_pubkey_sig.empty();
    if (pq_present) {
        if (pq_pubkey.size() != kPqPubBytes) {
            throw std::invalid_argument(
                "PrekeyRecord: pq_pubkey must be 1184B (ML-KEM-768)");
        }
        if (pq_pubkey_sig.size() != crypto_sign_BYTES) {
            throw std::invalid_argument(
                "PrekeyRecord: pq_pubkey_sig must be 64B");
        }
    }

    std::vector<std::uint8_t> out;
    const std::string magic = pq_present ? kPrekeyMagicV2 : kPrekeyMagic;
    out.insert(out.end(), magic.begin(), magic.end());
    out.push_back(32);
    out.insert(out.end(), publisher_pubkey.begin(), publisher_pubkey.end());
    out.push_back(32);
    out.insert(out.end(), signed_prekey.begin(), signed_prekey.end());
    out.push_back(64);
    out.insert(out.end(), signed_prekey_signature.begin(),
                signed_prekey_signature.end());
    auto append_be64 = [&](std::uint64_t v) {
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
        }
    };
    append_be64(published_at_ms);
    append_be64(ttl_ms);
    out.push_back(16);
    out.insert(out.end(), nonce.begin(), nonce.end());

    if (pq_present) {
        // pq_pub_len is big-endian u16 (1184 > 255 → can't use one byte).
        out.push_back(static_cast<std::uint8_t>((kPqPubBytes >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(kPqPubBytes & 0xff));
        out.insert(out.end(), pq_pubkey.begin(), pq_pubkey.end());
        out.push_back(64);
        out.insert(out.end(), pq_pubkey_sig.begin(), pq_pubkey_sig.end());
    }
    return out;
}

fb::proto::PrekeyRecord build_prekey_record(
    std::span<const std::uint8_t> sig_pub,
    std::span<const std::uint8_t> sig_priv,
    std::span<const std::uint8_t> signed_prekey,
    std::span<const std::uint8_t> signed_prekey_signature,
    std::uint64_t published_at_ms,
    std::uint64_t ttl_ms,
    std::span<const std::uint8_t> pq_pubkey,
    std::span<const std::uint8_t> pq_pubkey_sig) {
    if (sig_pub.size() != crypto_sign_PUBLICKEYBYTES) {
        throw std::invalid_argument("build_prekey_record: sig_pub must be 32B");
    }
    if (sig_priv.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::invalid_argument("build_prekey_record: sig_priv must be 64B");
    }
    fb::proto::PrekeyRecord out;
    out.set_publisher_pubkey(std::string(sig_pub.begin(), sig_pub.end()));
    out.set_signed_prekey(std::string(signed_prekey.begin(),
                                       signed_prekey.end()));
    out.set_signed_prekey_signature(std::string(
        signed_prekey_signature.begin(), signed_prekey_signature.end()));
    out.set_published_at_ms(published_at_ms);
    out.set_ttl_ms(ttl_ms);

    // PQ fields (Tier 7). When set, both flow into the record AND the v2
    // canonical signing bytes; when empty, the record stays v1 and old
    // validators accept it.
    const bool pq_present = !pq_pubkey.empty() || !pq_pubkey_sig.empty();
    if (pq_present) {
        out.set_pq_pubkey(std::string(pq_pubkey.begin(), pq_pubkey.end()));
        out.set_pq_pubkey_sig(std::string(
            pq_pubkey_sig.begin(), pq_pubkey_sig.end()));
    }

    std::array<std::uint8_t, 16> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    out.set_nonce(std::string(nonce.begin(), nonce.end()));

    auto signing_bytes = prekey_canonical_signing_bytes(
        sig_pub, signed_prekey, signed_prekey_signature,
        published_at_ms, ttl_ms,
        std::span<const std::uint8_t>(nonce.data(), nonce.size()),
        pq_pubkey, pq_pubkey_sig);
    std::array<std::uint8_t, crypto_sign_BYTES> sig{};
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              signing_bytes.data(), signing_bytes.size(),
                              sig_priv.data()) != 0) {
        throw std::runtime_error(
            "build_prekey_record: crypto_sign_detached failed");
    }
    out.set_signature(std::string(sig.begin(), sig.begin() + sig_len));
    return out;
}

namespace {

bool verify_prekey_record_signature(const fb::proto::PrekeyRecord& r) {
    if (r.publisher_pubkey().size() != crypto_sign_PUBLICKEYBYTES) return false;
    if (r.signed_prekey().size() != 32) return false;
    if (r.signed_prekey_signature().size() != crypto_sign_BYTES) return false;
    if (r.signature().size() != crypto_sign_BYTES) return false;
    if (r.nonce().size() != 16) return false;
    // PQ fields are all-or-nothing.
    const bool pq_present = !r.pq_pubkey().empty() || !r.pq_pubkey_sig().empty();
    if (pq_present) {
        if (r.pq_pubkey().size() != kPqPubBytes) return false;
        if (r.pq_pubkey_sig().size() != crypto_sign_BYTES) return false;
    }
    auto pub = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.publisher_pubkey().data()),
        r.publisher_pubkey().size());
    auto spk = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.signed_prekey().data()),
        r.signed_prekey().size());
    auto spk_sig = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.signed_prekey_signature().data()),
        r.signed_prekey_signature().size());
    auto nonce = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.nonce().data()),
        r.nonce().size());
    auto pq_pub_span = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.pq_pubkey().data()),
        r.pq_pubkey().size());
    auto pq_sig_span = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(r.pq_pubkey_sig().data()),
        r.pq_pubkey_sig().size());
    auto signing_bytes = prekey_canonical_signing_bytes(
        pub, spk, spk_sig, r.published_at_ms(), r.ttl_ms(), nonce,
        pq_pub_span, pq_sig_span);
    if (0 != crypto_sign_verify_detached(
            reinterpret_cast<const unsigned char*>(r.signature().data()),
            signing_bytes.data(), signing_bytes.size(), pub.data())) {
        return false;
    }
    // Independent SPK signature check — guards against a peer
    // republishing the OUTER record with a different SPK they don't
    // own. The SPK signature is over the SPK bytes alone, signed by
    // the identity key.
    if (0 != crypto_sign_verify_detached(
            reinterpret_cast<const unsigned char*>(r.signed_prekey_signature().data()),
            reinterpret_cast<const unsigned char*>(r.signed_prekey().data()),
            r.signed_prekey().size(), pub.data())) {
        return false;
    }
    // PQ binding-sig check — same pattern as the SPK signature, signed by
    // the identity key over pq_pubkey bytes alone. Guards against a peer
    // republishing the OUTER record with a swapped PQ key they don't own.
    if (pq_present) {
        if (0 != crypto_sign_verify_detached(
                reinterpret_cast<const unsigned char*>(r.pq_pubkey_sig().data()),
                reinterpret_cast<const unsigned char*>(r.pq_pubkey().data()),
                r.pq_pubkey().size(), pub.data())) {
            return false;
        }
    }
    return true;
}

bool prekey_expired(const fb::proto::PrekeyRecord& r, std::uint64_t now_ms) {
    return r.published_at_ms() + r.ttl_ms() <= now_ms;
}

std::string prekey_record_key(const fb::proto::PrekeyRecord& r) {
    std::string out;
    out.reserve(r.publisher_pubkey().size() + r.nonce().size());
    out.append(r.publisher_pubkey());
    out.append(r.nonce());
    return out;
}

}  // namespace

struct PrekeyStore::Impl {
    std::map<std::string,
             std::map<std::string, fb::proto::PrekeyRecord>> by_publisher;
};

PrekeyStore::PrekeyStore()  : impl_(std::make_unique<Impl>()) {}
PrekeyStore::~PrekeyStore() = default;

PrekeyStore::PutResult PrekeyStore::put(
    const fb::proto::PrekeyRecord& record, std::uint64_t now_ms) {
    if (record.publisher_pubkey().size() != crypto_sign_PUBLICKEYBYTES)
        return PutResult::kRejectedFormat;
    if (record.signed_prekey().size() != 32)
        return PutResult::kRejectedFormat;
    if (record.signed_prekey_signature().size() != crypto_sign_BYTES)
        return PutResult::kRejectedFormat;
    if (record.signature().size() != crypto_sign_BYTES)
        return PutResult::kRejectedFormat;
    if (record.nonce().size() != 16)
        return PutResult::kRejectedFormat;

    const auto now = now_ms_or(now_ms);
    if (record.published_at_ms() > now + kRecordClockSkewMs)
        return PutResult::kRejectedClock;
    if (prekey_expired(record, now))
        return PutResult::kRejectedExpired;
    if (!verify_prekey_record_signature(record))
        return PutResult::kRejectedSig;

    auto pkey = pubkey_key(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(record.publisher_pubkey().data()),
        record.publisher_pubkey().size()));
    auto rkey = prekey_record_key(record);
    auto& bucket = impl_->by_publisher[pkey];
    auto [it, inserted] = bucket.try_emplace(rkey, record);
    return inserted ? PutResult::kAccepted : PutResult::kAlreadyKnown;
}

std::optional<fb::proto::PrekeyRecord> PrekeyStore::get_latest(
    std::span<const std::uint8_t> publisher_pubkey,
    std::uint64_t now_ms) const {
    const auto now = now_ms_or(now_ms);
    auto pkey = pubkey_key(publisher_pubkey);
    auto it = impl_->by_publisher.find(pkey);
    if (it == impl_->by_publisher.end()) return std::nullopt;
    std::optional<fb::proto::PrekeyRecord> best;
    for (const auto& [_rk, rec] : it->second) {
        if (prekey_expired(rec, now)) continue;
        if (!best || rec.published_at_ms() > best->published_at_ms()) {
            best = rec;
        }
    }
    return best;
}

std::vector<fb::proto::PrekeyRecord> PrekeyStore::get_all(
    std::span<const std::uint8_t> publisher_pubkey,
    std::uint64_t now_ms) const {
    const auto now = now_ms_or(now_ms);
    std::vector<fb::proto::PrekeyRecord> out;
    auto pkey = pubkey_key(publisher_pubkey);
    auto it = impl_->by_publisher.find(pkey);
    if (it == impl_->by_publisher.end()) return out;
    for (const auto& [_rk, rec] : it->second) {
        if (!prekey_expired(rec, now)) out.push_back(rec);
    }
    return out;
}

std::size_t PrekeyStore::prune_expired(std::uint64_t now_ms) {
    const auto now = now_ms_or(now_ms);
    std::size_t pruned = 0;
    for (auto pit = impl_->by_publisher.begin();
         pit != impl_->by_publisher.end();) {
        auto& bucket = pit->second;
        for (auto rit = bucket.begin(); rit != bucket.end();) {
            if (prekey_expired(rit->second, now)) {
                rit = bucket.erase(rit);
                ++pruned;
            } else {
                ++rit;
            }
        }
        if (bucket.empty()) pit = impl_->by_publisher.erase(pit);
        else ++pit;
    }
    return pruned;
}

std::size_t PrekeyStore::size() const {
    std::size_t n = 0;
    for (const auto& [_pk, bucket] : impl_->by_publisher) n += bucket.size();
    return n;
}

}  // namespace fb::p2p
