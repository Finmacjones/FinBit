// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/ratchet.hpp"

#include <sodium.h>

#include <array>
#include <cstring>
#include <map>
#include <stdexcept>
#include <utility>
#include <vector>

#include "fb/crypto/aead.hpp"
#include "fb/crypto/hkdf.hpp"
#include "ratchet.pb.h"

namespace fb::crypto {
namespace {

constexpr std::size_t k32 = 32;
constexpr std::array<std::uint8_t, 1> kHmacInfoMk{0x01};
constexpr std::array<std::uint8_t, 1> kHmacInfoCk{0x02};
constexpr std::string_view kRkInfo = "FinBit-RK";

void ensure_sodium() {
    static const int rc = sodium_init();
    if (rc < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

using Bytes32 = std::array<std::uint8_t, k32>;

// X25519 keypair generation. libsodium gives us crypto_kx_keypair which
// returns Curve25519 keys suitable for crypto_scalarmult.
std::pair<Bytes32, Bytes32> x25519_keypair() {
    Bytes32 pub{};
    Bytes32 priv{};
    randombytes_buf(priv.data(), priv.size());
    if (crypto_scalarmult_base(pub.data(), priv.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult_base failed");
    }
    return {pub, priv};
}

// Compute X25519 DH (priv * peer_pub).
Bytes32 x25519_dh(const Bytes32& priv, const Bytes32& peer_pub) {
    Bytes32 out{};
    if (crypto_scalarmult(out.data(), priv.data(), peer_pub.data()) != 0) {
        // crypto_scalarmult only fails for low-order outputs; treat as fatal.
        throw std::runtime_error("crypto_scalarmult produced low-order output");
    }
    return out;
}

// HKDF-SHA256: salt+ikm -> 64 bytes via Extract+Expand. Returns (RK', CK').
std::pair<Bytes32, Bytes32> kdf_rk(const Bytes32& rk, const Bytes32& dh_out) {
    auto prk = hkdf_extract(std::span<const std::uint8_t>(rk.data(), rk.size()),
                            std::span<const std::uint8_t>(dh_out.data(), dh_out.size()));
    auto out = hkdf_expand(prk,
                           std::span<const std::uint8_t>(
                               reinterpret_cast<const std::uint8_t*>(kRkInfo.data()),
                               kRkInfo.size()),
                           64);
    Bytes32 new_rk{};
    Bytes32 new_ck{};
    std::memcpy(new_rk.data(), out.data(), k32);
    std::memcpy(new_ck.data(), out.data() + k32, k32);
    return {new_rk, new_ck};
}

// Symmetric chain step: HMAC-SHA256(ck, 0x01) -> mk; HMAC-SHA256(ck, 0x02) -> ck'.
std::pair<Bytes32, Bytes32> kdf_ck(const Bytes32& ck) {
    Bytes32 mk{};
    Bytes32 new_ck{};
    if (crypto_auth_hmacsha256(mk.data(), kHmacInfoMk.data(), kHmacInfoMk.size(), ck.data()) !=
        0) {
        throw std::runtime_error("hmac-sha256 (mk) failed");
    }
    if (crypto_auth_hmacsha256(new_ck.data(), kHmacInfoCk.data(), kHmacInfoCk.size(), ck.data()) !=
        0) {
        throw std::runtime_error("hmac-sha256 (ck) failed");
    }
    return {mk, new_ck};
}

}  // namespace

// -----------------------------------------------------------------------------
// State

struct DoubleRatchet::State {
    Bytes32 dhs_pub{};
    Bytes32 dhs_priv{};
    Bytes32 dhr_pub{};       // peer's current DH public; meaningful iff have_dhr
    bool    have_dhr = false;
    Bytes32 rk{};
    Bytes32 cks{};
    Bytes32 ckr{};
    bool    have_cks = false;
    bool    have_ckr = false;
    std::uint32_t ns = 0;
    std::uint32_t nr = 0;
    std::uint32_t pn = 0;

    // (peer_dh_pub, n) -> message_key. We use a flat std::map for the cache;
    // ordering keeps eviction simple. Total cap kMaxSkip across all entries.
    std::map<std::pair<Bytes32, std::uint32_t>, Bytes32> skipped;

    // Wipe every byte that could be live key material: dhs_priv (our DH
    // private key), rk (root key), cks/ckr (chain keys), and every cached
    // skipped message key. Without this, a freed State page sits in the
    // allocator with the keys still readable until the page is reused.
    // Caught by the security validation pass — defaulted ~State left
    // these unwiped. Factored out of ~State so try_decrypt can zero a
    // MUTATED state before rolling it back (the std::map reassignment in
    // copy-assign destroys nodes with the trivial Bytes32 dtor, which
    // does NOT zero — so a failed decrypt would otherwise leak the
    // message keys decrypt() derived before the MAC check).
    void secure_wipe() {
        sodium_memzero(dhs_priv.data(), dhs_priv.size());
        sodium_memzero(rk.data(),       rk.size());
        sodium_memzero(cks.data(),      cks.size());
        sodium_memzero(ckr.data(),      ckr.size());
        sodium_memzero(dhs_pub.data(),  dhs_pub.size());
        sodium_memzero(dhr_pub.data(),  dhr_pub.size());
        for (auto& [k, mk] : skipped) {
            sodium_memzero(mk.data(), mk.size());
        }
    }
    ~State() { secure_wipe(); }
};

DoubleRatchet::DoubleRatchet() : state_(std::make_unique<State>()) {}
DoubleRatchet::~DoubleRatchet() = default;
DoubleRatchet::DoubleRatchet(DoubleRatchet&&) noexcept = default;
DoubleRatchet& DoubleRatchet::operator=(DoubleRatchet&&) noexcept = default;

DoubleRatchet DoubleRatchet::init_alice(std::span<const std::uint8_t, 32> shared_secret,
                                        std::span<const std::uint8_t, 32> peer_dh_pub) {
    ensure_sodium();
    DoubleRatchet r;
    auto& s = *r.state_;
    auto [pub, priv] = x25519_keypair();
    s.dhs_pub = pub;
    s.dhs_priv = priv;
    std::memcpy(s.dhr_pub.data(), peer_dh_pub.data(), k32);
    s.have_dhr = true;
    Bytes32 sk{};
    std::memcpy(sk.data(), shared_secret.data(), k32);
    auto dh = x25519_dh(s.dhs_priv, s.dhr_pub);
    auto [new_rk, new_ck] = kdf_rk(sk, dh);
    s.rk = new_rk;
    s.cks = new_ck;
    s.have_cks = true;
    return r;
}

DoubleRatchet DoubleRatchet::init_bob(std::span<const std::uint8_t, 32> shared_secret,
                                      std::span<const std::uint8_t, 32> our_priv,
                                      std::span<const std::uint8_t, 32> our_pub) {
    ensure_sodium();
    DoubleRatchet r;
    auto& s = *r.state_;
    std::memcpy(s.dhs_pub.data(), our_pub.data(), k32);
    std::memcpy(s.dhs_priv.data(), our_priv.data(), k32);
    s.have_dhr = false;
    std::memcpy(s.rk.data(), shared_secret.data(), k32);
    s.have_cks = false;
    s.have_ckr = false;
    return r;
}

// -----------------------------------------------------------------------------
// Encrypt

std::vector<std::uint8_t> DoubleRatchet::encrypt(std::span<const std::uint8_t> plaintext,
                                                 std::span<const std::uint8_t> outer_aad) {
    auto& s = *state_;
    if (!s.have_cks) {
        throw std::logic_error(
            "DoubleRatchet::encrypt: send chain is empty (Bob must receive Alice's first "
            "message before he can send)");
    }
    auto [mk, new_cks] = kdf_ck(s.cks);
    s.cks = new_cks;

    fb::proto::RatchetMessage msg;
    msg.set_header_dh_pub(std::string(reinterpret_cast<const char*>(s.dhs_pub.data()), k32));
    msg.set_pn(s.pn);
    msg.set_n(s.ns);

    // Compose AEAD AAD = serialized header fields || outer_aad. The header is
    // covered so a relay cannot rewrite n / pn / dh_pub without invalidating
    // the tag.
    std::vector<std::uint8_t> aad;
    aad.reserve(k32 + 4 + 4 + outer_aad.size());
    aad.insert(aad.end(), s.dhs_pub.begin(), s.dhs_pub.end());
    auto u32_be = [](std::uint32_t v, std::vector<std::uint8_t>& out) {
        out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(v & 0xff));
    };
    u32_be(s.pn, aad);
    u32_be(s.ns, aad);
    aad.insert(aad.end(), outer_aad.begin(), outer_aad.end());

    AeadKey key{};
    std::memcpy(key.data(), mk.data(), key.size());
    XChaChaNonce nonce{};  // zero 24-byte nonce: safe because mk is fresh
    // XChaCha20-Poly1305 chosen so the ratchet works on every CPU (incl.
    // WASM where AES-NI is unavailable). Same security argument as before:
    // each message key is derived once via HMAC-SHA256(ck, 0x01) and used
    // exactly once.
    auto ct = xchacha20_encrypt(key, nonce, plaintext, aad);
    msg.set_ciphertext(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));

    s.ns += 1;

    std::vector<std::uint8_t> out(msg.ByteSizeLong());
    if (!msg.SerializeToArray(out.data(), static_cast<int>(out.size()))) {
        throw std::runtime_error("RatchetMessage serialize failed");
    }
    return out;
}

// -----------------------------------------------------------------------------
// Decrypt — including DH ratchet step + skipped-key cache lookup

namespace {

void skip_message_keys(DoubleRatchet::State& s, std::uint32_t until) {
    if (!s.have_ckr) return;
    if (until > s.nr + DoubleRatchet::kMaxSkip) {
        throw std::runtime_error("skip exceeds MAX_SKIP — refusing to advance receive chain");
    }
    while (s.nr < until) {
        auto [mk, new_ckr] = kdf_ck(s.ckr);
        s.ckr = new_ckr;
        if (s.skipped.size() >= DoubleRatchet::kMaxSkip) {
            // Evict oldest (map ordering by (dhr_pub, n) — adequate for Phase 0).
            s.skipped.erase(s.skipped.begin());
        }
        s.skipped.emplace(std::make_pair(s.dhr_pub, s.nr), mk);
        s.nr += 1;
    }
}

void dh_ratchet(DoubleRatchet::State& s, const Bytes32& header_dh_pub) {
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    s.dhr_pub = header_dh_pub;
    s.have_dhr = true;
    {
        auto dh = x25519_dh(s.dhs_priv, s.dhr_pub);
        auto [new_rk, new_ck] = kdf_rk(s.rk, dh);
        s.rk = new_rk;
        s.ckr = new_ck;
        s.have_ckr = true;
    }
    auto [pub, priv] = x25519_keypair();
    s.dhs_pub = pub;
    s.dhs_priv = priv;
    {
        auto dh = x25519_dh(s.dhs_priv, s.dhr_pub);
        auto [new_rk, new_ck] = kdf_rk(s.rk, dh);
        s.rk = new_rk;
        s.cks = new_ck;
        s.have_cks = true;
    }
}

std::vector<std::uint8_t> compose_aad(const Bytes32& header_dh_pub, std::uint32_t pn,
                                      std::uint32_t n, std::span<const std::uint8_t> outer) {
    std::vector<std::uint8_t> aad;
    aad.reserve(k32 + 8 + outer.size());
    aad.insert(aad.end(), header_dh_pub.begin(), header_dh_pub.end());
    auto u32_be = [&](std::uint32_t v) {
        aad.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
        aad.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
        aad.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
        aad.push_back(static_cast<std::uint8_t>(v & 0xff));
    };
    u32_be(pn);
    u32_be(n);
    aad.insert(aad.end(), outer.begin(), outer.end());
    return aad;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> DoubleRatchet::decrypt(
    std::span<const std::uint8_t> ratchet_msg, std::span<const std::uint8_t> outer_aad) {
    fb::proto::RatchetMessage msg;
    if (!msg.ParseFromArray(ratchet_msg.data(), static_cast<int>(ratchet_msg.size()))) {
        return std::nullopt;
    }
    if (msg.header_dh_pub().size() != k32) {
        return std::nullopt;
    }
    Bytes32 header_dh{};
    std::memcpy(header_dh.data(), msg.header_dh_pub().data(), k32);

    auto& s = *state_;

    // 1. Try skipped keys first (covers reordered or out-of-order delivery).
    {
        auto it = s.skipped.find(std::make_pair(header_dh, msg.n()));
        if (it != s.skipped.end()) {
            AeadKey key{};
            std::memcpy(key.data(), it->second.data(), key.size());
            XChaChaNonce nonce{};
            auto aad = compose_aad(header_dh, msg.pn(), msg.n(), outer_aad);
            auto ct = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(msg.ciphertext().data()),
                msg.ciphertext().size());
            auto pt = xchacha20_decrypt(key, nonce, ct, aad);
            // L1 (audit): consume the one-time skipped key ONLY after the
            // AEAD tag verifies. Erasing before decrypt would permanently
            // drop the key for a direct decrypt() caller fed a corrupted or
            // forged ciphertext, destroying the ability to ever decrypt the
            // genuine out-of-order message this key was saved for. (`it`
            // stays valid — the map isn't mutated across the decrypt.)
            if (pt) s.skipped.erase(it);
            return pt;
        }
    }

    // 2. New peer DH key? Skip to end of current recv chain, then DH ratchet.
    if (!s.have_dhr || header_dh != s.dhr_pub) {
        try {
            skip_message_keys(s, msg.pn());
        } catch (...) {
            return std::nullopt;
        }
        dh_ratchet(s, header_dh);
    }

    // 3. Skip up to msg.n() in the (possibly new) receive chain.
    try {
        skip_message_keys(s, msg.n());
    } catch (...) {
        return std::nullopt;
    }

    // 4. Derive the key for this message and consume it.
    auto [mk, new_ckr] = kdf_ck(s.ckr);
    s.ckr = new_ckr;
    s.nr += 1;

    AeadKey key{};
    std::memcpy(key.data(), mk.data(), key.size());
    XChaChaNonce nonce{};
    auto aad = compose_aad(header_dh, msg.pn(), msg.n(), outer_aad);
    auto ct = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(msg.ciphertext().data()), msg.ciphertext().size());
    return xchacha20_decrypt(key, nonce, ct, aad);
}

std::optional<std::vector<std::uint8_t>> DoubleRatchet::try_decrypt(
    std::span<const std::uint8_t> ratchet_msg, std::span<const std::uint8_t> outer_aad) {
    // Snapshot the entire State so a failed AEAD verify leaves no trace
    // (the existing decrypt() mutates state — derives the message key
    // via kdf_ck and advances ckr/nr — BEFORE the MAC check; reusing the
    // session afterward would skip a chain step and never re-derive the
    // missed message key). The State's std::map<skipped> copy is the
    // only allocation here; everything else is byte-array copy.
    //
    // Rollback semantics: on nullopt return, state_ is byte-identical to
    // what it was before the call. On success, state_ reflects exactly
    // what decrypt() would have produced. Either way, the caller can
    // call try_decrypt again — or fall back to decrypt — safely.
    //
    // KEY HYGIENE: State has a user-declared destructor, so it has no
    // implicit move operations — the assignment below is a deep COPY,
    // and the std::map reassignment destroys the mutated state's nodes
    // with the trivial Bytes32 destructor (NOT sodium_memzero). On a
    // failed decrypt, *state_ may hold up to kMaxSkip message keys that
    // decrypt() derived before the MAC check; we must zero them BEFORE
    // the copy-assign overwrites the map, or they leak into freed heap.
    State snapshot = *state_;
    auto pt = decrypt(ratchet_msg, outer_aad);
    if (!pt) {
        state_->secure_wipe();   // zero keys decrypt() may have derived
        *state_ = snapshot;      // restore the pre-attempt state (deep copy)
    }
    return pt;
}

bool DoubleRatchet::header_matches_recv_chain(
    std::span<const std::uint8_t> ratchet_msg) const noexcept {
    fb::proto::RatchetMessage msg;
    if (!msg.ParseFromArray(ratchet_msg.data(),
                            static_cast<int>(ratchet_msg.size()))) {
        return false;
    }
    if (msg.header_dh_pub().size() != k32) return false;

    const auto& s = *state_;
    // Only meaningful once we have a receive chain established.
    if (!s.have_dhr || !s.have_ckr) return false;

    // DoS guard: reject absurd skip distances WITHOUT deriving any key.
    // A genuine in-order/small-skip message has n within kMaxSkip of our
    // current receive counter; an attacker-crafted n = 2^32-1 is rejected
    // here. (pn matters only on a DH-ratchet, which is the fallback path.)
    if (msg.n() > s.nr &&
        static_cast<std::uint64_t>(msg.n()) - s.nr > kMaxSkip) {
        return false;
    }

    // The cheap positive signal: this message's header DH equals the peer
    // DH key of our CURRENT receive chain. True for every in-order and
    // small-skip message on this session; a mismatch means it belongs to
    // a different session (or a DH-ratcheted state handled by fallback).
    return std::memcmp(msg.header_dh_pub().data(), s.dhr_pub.data(), k32) == 0;
}

}  // namespace fb::crypto
