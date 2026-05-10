// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/sender_keys.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "fb/crypto/aead.hpp"
#include "sender_keys.pb.h"

namespace fb::crypto {
namespace {

constexpr std::array<std::uint8_t, 1> kInfoMk{0x10};
constexpr std::array<std::uint8_t, 1> kInfoCk{0x11};

void ensure_sodium() {
    static const int rc = sodium_init();
    if (rc < 0) throw std::runtime_error("libsodium init failed");
}

std::array<std::uint8_t, 32> hmac(std::span<const std::uint8_t, 32> key,
                                  std::span<const std::uint8_t> info) {
    std::array<std::uint8_t, 32> out{};
    if (crypto_auth_hmacsha256(out.data(), info.data(), info.size(), key.data()) != 0) {
        throw std::runtime_error("hmac-sha256 failed");
    }
    return out;
}

std::vector<std::uint8_t> compose_aad(std::span<const std::uint8_t> chain_id, std::uint32_t index,
                                      std::span<const std::uint8_t> outer) {
    std::vector<std::uint8_t> aad;
    aad.reserve(chain_id.size() + 4 + outer.size());
    aad.insert(aad.end(), chain_id.begin(), chain_id.end());
    aad.push_back(static_cast<std::uint8_t>((index >> 24) & 0xff));
    aad.push_back(static_cast<std::uint8_t>((index >> 16) & 0xff));
    aad.push_back(static_cast<std::uint8_t>((index >> 8) & 0xff));
    aad.push_back(static_cast<std::uint8_t>(index & 0xff));
    aad.insert(aad.end(), outer.begin(), outer.end());
    return aad;
}

}  // namespace

std::array<std::uint8_t, 32> derive_message_key(std::span<const std::uint8_t, 32> ck) {
    return hmac(ck, std::span<const std::uint8_t>(kInfoMk.data(), kInfoMk.size()));
}

std::array<std::uint8_t, 32> ratchet_chain_key(std::span<const std::uint8_t, 32> ck) {
    return hmac(ck, std::span<const std::uint8_t>(kInfoCk.data(), kInfoCk.size()));
}

// -----------------------------------------------------------------------------
// SenderChain

SenderChain::SenderChain(std::span<const std::uint8_t, 32> seed) {
    std::memcpy(chain_key_.data(), seed.data(), 32);
}

std::vector<std::uint8_t> SenderChain::encrypt(std::span<const std::uint8_t> /*plaintext*/,
                                               std::span<const std::uint8_t> /*aad*/) {
    throw std::logic_error(
        "SenderChain::encrypt: callers should use GroupSession::encrypt instead "
        "(SenderChain is the per-sender state piece, not a standalone API)");
}

// -----------------------------------------------------------------------------
// GroupSession

struct PerPeerChain {
    std::array<std::uint8_t, 16> chain_id{};
    std::array<std::uint8_t, 32> chain_key{};
    std::uint32_t                next_index = 0;
    // Skipped message keys keyed by (chain_id, index).
    std::map<std::pair<std::array<std::uint8_t, 16>, std::uint32_t>,
             std::array<std::uint8_t, 32>>
        skipped;

    ~PerPeerChain() {
        sodium_memzero(chain_key.data(), chain_key.size());
        for (auto& [k, mk] : skipped) {
            sodium_memzero(mk.data(), mk.size());
        }
    }
};

struct GroupSession::Impl {
    // Sender side.
    std::array<std::uint8_t, 16> own_chain_id{};
    std::array<std::uint8_t, 32> own_chain_key{};
    std::uint32_t                own_next_index = 0;
    bool                         have_own_chain = false;

    // Receiver side: peer_id -> chain.
    std::map<std::string, PerPeerChain> peers;

    // Wipe the sender-side chain key on destruction. Per-peer chains
    // wipe themselves via PerPeerChain::~PerPeerChain when the map is
    // destroyed. Caught by the security validation pass — defaulted
    // ~Impl left these unwiped.
    ~Impl() {
        sodium_memzero(own_chain_key.data(), own_chain_key.size());
    }
};

GroupSession::GroupSession() : impl_(std::make_unique<Impl>()) {}
GroupSession::~GroupSession() = default;
GroupSession::GroupSession(GroupSession&&) noexcept = default;
GroupSession& GroupSession::operator=(GroupSession&&) noexcept = default;

std::vector<std::uint8_t> GroupSession::create_own_send_chain() {
    ensure_sodium();
    randombytes_buf(impl_->own_chain_id.data(), impl_->own_chain_id.size());
    randombytes_buf(impl_->own_chain_key.data(), impl_->own_chain_key.size());
    impl_->own_next_index = 0;
    impl_->have_own_chain = true;

    fb::proto::SenderKeysDistribution d;
    d.set_chain_id(std::string(reinterpret_cast<const char*>(impl_->own_chain_id.data()),
                               impl_->own_chain_id.size()));
    d.set_chain_seed(std::string(reinterpret_cast<const char*>(impl_->own_chain_key.data()),
                                 impl_->own_chain_key.size()));
    d.set_start_index(0);

    std::vector<std::uint8_t> out(d.ByteSizeLong());
    if (!d.SerializeToArray(out.data(), static_cast<int>(out.size()))) {
        throw std::runtime_error("SenderKeysDistribution serialize failed");
    }
    return out;
}

std::vector<std::uint8_t> GroupSession::encrypt(std::span<const std::uint8_t> plaintext,
                                                std::span<const std::uint8_t> outer_aad) {
    if (!impl_->have_own_chain) {
        throw std::logic_error(
            "GroupSession::encrypt: own send chain not initialized (call "
            "create_own_send_chain first)");
    }
    auto mk = derive_message_key(impl_->own_chain_key);
    AeadKey key{};
    std::memcpy(key.data(), mk.data(), key.size());
    // XChaCha20-Poly1305: 24-byte zero nonce is safe — every message gets a
    // single-use derived key, and the nonce is bound by AAD anyway. Same
    // rationale as DoubleRatchet (and lets the WASM build run, which has no
    // AES-NI).
    XChaChaNonce nonce{};
    auto aad = compose_aad(
        std::span<const std::uint8_t>(impl_->own_chain_id.data(), impl_->own_chain_id.size()),
        impl_->own_next_index, outer_aad);
    auto ct = xchacha20_encrypt(key, nonce, plaintext, aad);

    fb::proto::SenderKeysMessage m;
    m.set_chain_id(std::string(reinterpret_cast<const char*>(impl_->own_chain_id.data()),
                               impl_->own_chain_id.size()));
    m.set_index(impl_->own_next_index);
    m.set_ciphertext(std::string(ct.begin(), ct.end()));
    std::vector<std::uint8_t> out(m.ByteSizeLong());
    if (!m.SerializeToArray(out.data(), static_cast<int>(out.size()))) {
        throw std::runtime_error("SenderKeysMessage serialize failed");
    }
    impl_->own_next_index += 1;
    impl_->own_chain_key = ratchet_chain_key(impl_->own_chain_key);
    return out;
}

void GroupSession::install_peer_distribution(std::span<const std::uint8_t> peer_id,
                                             std::span<const std::uint8_t> distribution) {
    fb::proto::SenderKeysDistribution d;
    if (!d.ParseFromArray(distribution.data(), static_cast<int>(distribution.size()))) {
        throw std::invalid_argument("malformed SenderKeysDistribution");
    }
    if (d.chain_id().size() != 16 || d.chain_seed().size() != 32) {
        throw std::invalid_argument("SenderKeysDistribution wrong field sizes");
    }
    PerPeerChain chain;
    std::memcpy(chain.chain_id.data(), d.chain_id().data(), 16);
    std::memcpy(chain.chain_key.data(), d.chain_seed().data(), 32);
    chain.next_index = d.start_index();
    std::string key(reinterpret_cast<const char*>(peer_id.data()), peer_id.size());
    impl_->peers[std::move(key)] = std::move(chain);
}

namespace {

bool advance_chain_to(PerPeerChain& chain, std::uint32_t target_index) {
    if (target_index < chain.next_index) {
        // Out-of-order: look in skipped cache (handled by caller).
        return false;
    }
    if (target_index - chain.next_index > GroupSession::kMaxSkip) {
        return false;
    }
    while (chain.next_index < target_index) {
        if (chain.skipped.size() >= GroupSession::kMaxSkip) {
            chain.skipped.erase(chain.skipped.begin());
        }
        chain.skipped.emplace(std::make_pair(chain.chain_id, chain.next_index),
                              derive_message_key(chain.chain_key));
        chain.chain_key = ratchet_chain_key(chain.chain_key);
        chain.next_index += 1;
    }
    return true;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> GroupSession::decrypt(
    std::span<const std::uint8_t> peer_id, std::span<const std::uint8_t> sender_keys_msg,
    std::span<const std::uint8_t> outer_aad) {
    fb::proto::SenderKeysMessage m;
    if (!m.ParseFromArray(sender_keys_msg.data(), static_cast<int>(sender_keys_msg.size()))) {
        return std::nullopt;
    }
    if (m.chain_id().size() != 16) return std::nullopt;
    std::array<std::uint8_t, 16> chain_id{};
    std::memcpy(chain_id.data(), m.chain_id().data(), 16);

    std::string key(reinterpret_cast<const char*>(peer_id.data()), peer_id.size());
    auto it = impl_->peers.find(key);
    if (it == impl_->peers.end()) return std::nullopt;
    auto& chain = it->second;
    // Distribution mismatch (likely a re-key the receiver hasn't been told
    // about yet).
    if (chain.chain_id != chain_id) return std::nullopt;

    XChaChaNonce nonce{};
    auto aad = compose_aad(std::span<const std::uint8_t>(chain_id.data(), chain_id.size()),
                           m.index(), outer_aad);

    // IMPORTANT: chain state is only mutated AFTER a successful AEAD verify.
    // Otherwise a single forged envelope would silently consume / advance
    // the chain so the next legitimate message at the same index would
    // either be replay-rejected (committed-then-failed) or lack its key
    // (skipped-key erased before failed decrypt). Both lose real messages.

    // 1. Skipped cache hit — try to open WITHOUT erasing first.
    {
        auto sk = chain.skipped.find(std::make_pair(chain_id, m.index()));
        if (sk != chain.skipped.end()) {
            AeadKey k{};
            std::memcpy(k.data(), sk->second.data(), k.size());
            auto pt = xchacha20_decrypt(
                k, nonce,
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(m.ciphertext().data()),
                    m.ciphertext().size()),
                std::span<const std::uint8_t>(aad.data(), aad.size()));
            if (!pt) return std::nullopt;       // forged — leave the key cached
            chain.skipped.erase(sk);            // legit — burn the one-shot key
            return pt;
        }
    }
    // 2. Replay (we already decrypted+consumed this index).
    if (m.index() < chain.next_index) return std::nullopt;
    // 3. Skip-too-far rejection. (Note: advance_chain_to populates skipped
    //    cache + advances chain; if a forger triggers it then fails the
    //    final decrypt below, the cache still holds the legit keys for any
    //    indices we ratcheted past, so subsequent real messages at those
    //    indices recover via the section-1 path.)
    if (!advance_chain_to(chain, m.index())) return std::nullopt;
    // 4. Derive key for this index, attempt decrypt, COMMIT only on success.
    auto mk = derive_message_key(chain.chain_key);
    AeadKey k{};
    std::memcpy(k.data(), mk.data(), k.size());
    auto pt = xchacha20_decrypt(k, nonce,
                                std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t*>(m.ciphertext().data()),
                                    m.ciphertext().size()),
                                std::span<const std::uint8_t>(aad.data(), aad.size()));
    if (!pt) return std::nullopt;
    chain.chain_key = ratchet_chain_key(chain.chain_key);
    chain.next_index += 1;
    return pt;
}

void GroupSession::remove_peer(std::span<const std::uint8_t> peer_id) {
    std::string key(reinterpret_cast<const char*>(peer_id.data()), peer_id.size());
    impl_->peers.erase(key);
}

std::size_t GroupSession::peer_count() const noexcept { return impl_->peers.size(); }

namespace {

void put_u32_be(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>((x >> 24) & 0xff));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xff));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xff));
    v.push_back(static_cast<std::uint8_t>(x & 0xff));
}

std::uint32_t read_u32_be(std::span<const std::uint8_t> v, std::size_t& off) {
    if (off + 4 > v.size()) throw std::runtime_error("read_u32_be underflow");
    std::uint32_t x = (static_cast<std::uint32_t>(v[off]) << 24) |
                      (static_cast<std::uint32_t>(v[off + 1]) << 16) |
                      (static_cast<std::uint32_t>(v[off + 2]) << 8) |
                      static_cast<std::uint32_t>(v[off + 3]);
    off += 4;
    return x;
}

void put_bytes(std::vector<std::uint8_t>& v, std::span<const std::uint8_t> b) {
    put_u32_be(v, static_cast<std::uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

std::vector<std::uint8_t> read_bytes(std::span<const std::uint8_t> v, std::size_t& off) {
    std::uint32_t n = read_u32_be(v, off);
    if (off + n > v.size()) throw std::runtime_error("read_bytes underflow");
    std::vector<std::uint8_t> out(v.begin() + off, v.begin() + off + n);
    off += n;
    return out;
}

constexpr std::uint32_t kStateMagic = 0x46425347;  // "FBSG"
constexpr std::uint32_t kStateVersion = 1;

}  // namespace

std::vector<std::uint8_t> GroupSession::serialize_state() const {
    std::vector<std::uint8_t> out;
    put_u32_be(out, kStateMagic);
    put_u32_be(out, kStateVersion);
    out.push_back(impl_->have_own_chain ? 1 : 0);
    if (impl_->have_own_chain) {
        out.insert(out.end(), impl_->own_chain_id.begin(), impl_->own_chain_id.end());
        out.insert(out.end(), impl_->own_chain_key.begin(), impl_->own_chain_key.end());
        put_u32_be(out, impl_->own_next_index);
    }
    put_u32_be(out, static_cast<std::uint32_t>(impl_->peers.size()));
    for (const auto& [peer_id, chain] : impl_->peers) {
        put_bytes(out, std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(peer_id.data()),
                            peer_id.size()));
        out.insert(out.end(), chain.chain_id.begin(), chain.chain_id.end());
        out.insert(out.end(), chain.chain_key.begin(), chain.chain_key.end());
        put_u32_be(out, chain.next_index);
        // Skipped-key cache deliberately not persisted — small in-memory
        // optimization that's recreated as out-of-order messages arrive.
    }
    return out;
}

std::unique_ptr<GroupSession> GroupSession::deserialize_state(
    std::span<const std::uint8_t> blob) {
    try {
        std::size_t off = 0;
        if (read_u32_be(blob, off) != kStateMagic) return nullptr;
        if (read_u32_be(blob, off) != kStateVersion) return nullptr;
        if (off >= blob.size()) return nullptr;
        const bool have_own = blob[off++] != 0;
        auto out = std::make_unique<GroupSession>();
        if (have_own) {
            if (off + 16 + 32 + 4 > blob.size()) return nullptr;
            std::memcpy(out->impl_->own_chain_id.data(), blob.data() + off, 16);
            off += 16;
            std::memcpy(out->impl_->own_chain_key.data(), blob.data() + off, 32);
            off += 32;
            out->impl_->own_next_index = read_u32_be(blob, off);
            out->impl_->have_own_chain = true;
        }
        const std::uint32_t n_peers = read_u32_be(blob, off);
        for (std::uint32_t i = 0; i < n_peers; ++i) {
            auto pid = read_bytes(blob, off);
            if (off + 16 + 32 + 4 > blob.size()) return nullptr;
            PerPeerChain c;
            std::memcpy(c.chain_id.data(), blob.data() + off, 16);
            off += 16;
            std::memcpy(c.chain_key.data(), blob.data() + off, 32);
            off += 32;
            c.next_index = read_u32_be(blob, off);
            std::string key(pid.begin(), pid.end());
            out->impl_->peers.emplace(std::move(key), std::move(c));
        }
        return out;
    } catch (...) {
        return nullptr;
    }
}

}  // namespace fb::crypto
