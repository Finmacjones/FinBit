// SPDX-License-Identifier: AGPL-3.0-or-later
// FinBit WASM shim — exposes a small subset of fb::core via embind so
// browser / Node.js code can drive identity + AEAD primitives.
//
// Built by scripts/build-wasm.sh into client-web/build/finbit.{js,wasm}.

#include <emscripten/bind.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "fb/crypto/aead.hpp"
#include "fb/crypto/hkdf.hpp"
#include "fb/crypto/identity.hpp"
#include "fb/crypto/ratchet.hpp"
#include "fb/crypto/sender_keys.hpp"

namespace {

// Convert a JS Uint8Array (passed as emscripten::val) into a std::vector.
std::vector<std::uint8_t> from_js_buffer(const emscripten::val& v) {
    const auto length = v["length"].as<unsigned>();
    std::vector<std::uint8_t> out(length);
    auto memory_view = emscripten::val(emscripten::typed_memory_view(out.size(), out.data()));
    memory_view.call<void>("set", v);
    return out;
}

emscripten::val to_js_uint8(const std::vector<std::uint8_t>& v) {
    return emscripten::val(
        emscripten::typed_memory_view(v.size(), v.data()))
        .call<emscripten::val>("slice", 0);
}

// Generate a fresh Ed25519 identity, return its base32 fingerprint.
std::string generate_identity_fingerprint() {
    auto id = fb::crypto::Identity::generate();
    return id.fingerprint();
}

// AES-256-GCM seal: takes Uint8Array(32) key, Uint8Array(12) nonce, Uint8Array
// plaintext, Uint8Array AAD. Returns a Uint8Array of ciphertext+tag. Throws
// (in JS) on key/nonce wrong size or AES-NI unavailable.
emscripten::val aead_encrypt(const emscripten::val& key, const emscripten::val& nonce,
                              const emscripten::val& pt, const emscripten::val& aad) {
    auto k = from_js_buffer(key);
    auto n = from_js_buffer(nonce);
    if (k.size() != 32 || n.size() != 12) {
        throw std::runtime_error("aead_encrypt: key must be 32 bytes, nonce must be 12 bytes");
    }
    fb::crypto::AeadKey ak{};
    fb::crypto::AeadNonce an{};
    std::memcpy(ak.data(), k.data(), 32);
    std::memcpy(an.data(), n.data(), 12);
    auto pt_v = from_js_buffer(pt);
    auto aad_v = from_js_buffer(aad);
    auto ct = fb::crypto::aead_encrypt(
        fb::crypto::AeadAlg::kAes256Gcm, ak, an,
        std::span<const std::uint8_t>(pt_v.data(), pt_v.size()),
        std::span<const std::uint8_t>(aad_v.data(), aad_v.size()));
    return to_js_uint8(ct);
}

// Returns Uint8Array of plaintext, or null on tag mismatch.
emscripten::val aead_decrypt(const emscripten::val& key, const emscripten::val& nonce,
                              const emscripten::val& ct, const emscripten::val& aad) {
    auto k = from_js_buffer(key);
    auto n = from_js_buffer(nonce);
    if (k.size() != 32 || n.size() != 12) {
        throw std::runtime_error("aead_decrypt: key must be 32 bytes, nonce must be 12 bytes");
    }
    fb::crypto::AeadKey ak{};
    fb::crypto::AeadNonce an{};
    std::memcpy(ak.data(), k.data(), 32);
    std::memcpy(an.data(), n.data(), 12);
    auto ct_v = from_js_buffer(ct);
    auto aad_v = from_js_buffer(aad);
    auto pt = fb::crypto::aead_decrypt(
        fb::crypto::AeadAlg::kAes256Gcm, ak, an,
        std::span<const std::uint8_t>(ct_v.data(), ct_v.size()),
        std::span<const std::uint8_t>(aad_v.data(), aad_v.size()));
    if (!pt) return emscripten::val::null();
    return to_js_uint8(*pt);
}

bool aes256gcm_supported() { return fb::crypto::aes256gcm_hw_available(); }

// XChaCha20-Poly1305 — software-only, always available, the recommended
// AEAD for WASM where AES-NI is gone.
emscripten::val xchacha20_encrypt(const emscripten::val& key, const emscripten::val& nonce,
                                   const emscripten::val& pt, const emscripten::val& aad) {
    auto k = from_js_buffer(key);
    auto n = from_js_buffer(nonce);
    if (k.size() != 32 || n.size() != 24) {
        throw std::runtime_error("xchacha20_encrypt: key=32B, nonce=24B required");
    }
    fb::crypto::AeadKey ak{};
    fb::crypto::XChaChaNonce xn{};
    std::memcpy(ak.data(), k.data(), 32);
    std::memcpy(xn.data(), n.data(), 24);
    auto pt_v = from_js_buffer(pt);
    auto aad_v = from_js_buffer(aad);
    auto ct = fb::crypto::xchacha20_encrypt(
        ak, xn,
        std::span<const std::uint8_t>(pt_v.data(), pt_v.size()),
        std::span<const std::uint8_t>(aad_v.data(), aad_v.size()));
    return to_js_uint8(ct);
}

emscripten::val xchacha20_decrypt(const emscripten::val& key, const emscripten::val& nonce,
                                   const emscripten::val& ct, const emscripten::val& aad) {
    auto k = from_js_buffer(key);
    auto n = from_js_buffer(nonce);
    if (k.size() != 32 || n.size() != 24) {
        throw std::runtime_error("xchacha20_decrypt: key=32B, nonce=24B required");
    }
    fb::crypto::AeadKey ak{};
    fb::crypto::XChaChaNonce xn{};
    std::memcpy(ak.data(), k.data(), 32);
    std::memcpy(xn.data(), n.data(), 24);
    auto ct_v = from_js_buffer(ct);
    auto aad_v = from_js_buffer(aad);
    auto pt = fb::crypto::xchacha20_decrypt(
        ak, xn,
        std::span<const std::uint8_t>(ct_v.data(), ct_v.size()),
        std::span<const std::uint8_t>(aad_v.data(), aad_v.size()));
    if (!pt) return emscripten::val::null();
    return to_js_uint8(*pt);
}

// =============================================================================
// seal_seed / open_seed — passphrase-protect the 32-byte Ed25519 seed for
// at-rest storage in IndexedDB (browser) / disk (eventually). Argon2id stretches
// the passphrase; XChaCha20-Poly1305 then seals the seed.
//
// Wire format v2 (105 bytes):
//   [version=2 (1)] [salt(16)] [opslimit(u64 BE)] [memlimit(u64 BE)]
//     [nonce(24)] [ct+tag(48)]
// AAD = first 33 bytes (version || salt || ops || mem). Binding the params
// into AAD means a tamper of any structural byte invalidates the AEAD tag,
// closing the "low bit of memlimit doesn't change Argon2 output, AEAD tag
// still matches" downgrade path that v1 had.
//
// Wire format v1 (104 bytes):
//   [salt(16)] [opslimit(u64 BE)] [memlimit(u64 BE)] [nonce(24)] [ct+tag(48)]
// Still readable for backwards compat; sealed only via legacy code paths.
// =============================================================================

constexpr std::size_t kV1Bytes =
    crypto_pwhash_SALTBYTES + 8 + 8 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
    fb::crypto::kIdentitySeedBytes + crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::size_t kV2Bytes      = 1 + kV1Bytes;
constexpr std::uint8_t kVaultVersion = 2;

// Defensive bounds applied on OPEN. A read-write attacker who downgrades a
// stored vault to MIN-tier params can otherwise brute-force at millions of
// guesses per second offline. We refuse anything weaker than INTERACTIVE
// and reject memlimit > 1 GiB (no realistic device exceeds that for a
// login). These bounds intentionally still ACCEPT existing INTERACTIVE
// vaults so old vaults open in-place; new vaults are written at MODERATE.
constexpr std::uint64_t kMinOpslimit = 2;            // == INTERACTIVE
constexpr std::uint64_t kMinMemlimit = 64u * 1024u * 1024u;  // == INTERACTIVE
constexpr std::uint64_t kMaxMemlimit = 1024u * 1024u * 1024u; // 1 GiB

void put_u64_be(std::uint8_t* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) { p[i] = static_cast<std::uint8_t>(v & 0xff); v >>= 8; }
}
std::uint64_t get_u64_be(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

// Sodium init is idempotent and returns 0 on success, 1 if already
// initialised, -1 on failure. Anything other than -1 means we're good.
void ensure_sodium() {
    if (sodium_init() == -1) {
        throw std::runtime_error("libsodium init failed");
    }
}

emscripten::val seal_seed_with_params(const std::string& passphrase,
                                       const emscripten::val& seed_js,
                                       std::uint64_t opslimit,
                                       std::uint64_t memlimit) {
    ensure_sodium();
    auto seed = from_js_buffer(seed_js);
    if (seed.size() != fb::crypto::kIdentitySeedBytes) {
        throw std::runtime_error("seal_seed: seed must be 32 bytes");
    }
    if (passphrase.empty()) {
        throw std::runtime_error("seal_seed: passphrase must not be empty");
    }

    std::vector<std::uint8_t> blob(kV2Bytes);
    blob[0] = kVaultVersion;
    std::uint8_t* salt    = blob.data() + 1;
    std::uint8_t* opsbuf  = salt + crypto_pwhash_SALTBYTES;
    std::uint8_t* membuf  = opsbuf + 8;
    std::uint8_t* nonce   = membuf + 8;
    std::uint8_t* ctpos   = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    randombytes_buf(salt,  crypto_pwhash_SALTBYTES);
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    put_u64_be(opsbuf, opslimit);
    put_u64_be(membuf, memlimit);

    std::array<std::uint8_t, 32> kdf_out{};
    if (crypto_pwhash(kdf_out.data(), kdf_out.size(),
                      passphrase.data(), passphrase.size(),
                      salt, opslimit, static_cast<std::size_t>(memlimit),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(kdf_out.data(), kdf_out.size());
        throw std::runtime_error("seal_seed: argon2id derivation failed (out of memory?)");
    }

    // AAD = the entire pre-nonce header. Any tamper of version, salt,
    // ops, or mem invalidates the AEAD tag.
    const std::size_t aad_len = static_cast<std::size_t>(nonce - blob.data());
    unsigned long long ct_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ctpos, &ct_len, seed.data(), seed.size(),
        blob.data(), aad_len, /*nsec=*/nullptr,
        nonce, kdf_out.data());
    sodium_memzero(kdf_out.data(), kdf_out.size());
    if (rc != 0) throw std::runtime_error("seal_seed: aead encrypt failed");
    return to_js_uint8(blob);
}

emscripten::val seal_seed(const std::string& passphrase, const emscripten::val& seed_js) {
    // Default tier bumped to MODERATE (~256 MiB / ~1.5s on a desktop CPU)
    // so a stolen vault costs ~10s of GPU-hours per million guesses.
    return seal_seed_with_params(passphrase, seed_js,
                                  crypto_pwhash_OPSLIMIT_MODERATE,
                                  crypto_pwhash_MEMLIMIT_MODERATE);
}

// Returns Uint8Array(32) seed on success, null on wrong passphrase / tamper /
// malformed blob / params out of allowed range. Throws only on KDF
// allocation failure (OOM).
emscripten::val open_seed(const std::string& passphrase, const emscripten::val& blob_js) {
    ensure_sodium();
    auto blob = from_js_buffer(blob_js);

    // Detect format version. v2 has a leading version byte; v1 is exactly
    // 104 bytes long and starts with random salt.
    bool v2 = (blob.size() == kV2Bytes && blob[0] == kVaultVersion);
    bool v1 = (blob.size() == kV1Bytes);
    if (!v1 && !v2) return emscripten::val::null();

    const std::uint8_t* salt   = blob.data() + (v2 ? 1 : 0);
    const std::uint8_t* opsbuf = salt + crypto_pwhash_SALTBYTES;
    const std::uint8_t* membuf = opsbuf + 8;
    const std::uint8_t* nonce  = membuf + 8;
    const std::uint8_t* ct     = nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const std::size_t   ct_len = blob.size() - static_cast<std::size_t>(ct - blob.data());

    const std::uint64_t ops = get_u64_be(opsbuf);
    const std::uint64_t mem = get_u64_be(membuf);
    // Refuse out-of-range params. Lower bound stops a write-capable
    // attacker from downgrading the work factor; upper bound stops a
    // tampered blob from triggering an Argon2 OOM-/-hang DoS.
    if (mem > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        mem > kMaxMemlimit || mem < kMinMemlimit ||
        ops < kMinOpslimit) {
        return emscripten::val::null();
    }

    std::array<std::uint8_t, 32> kdf_out{};
    if (crypto_pwhash(kdf_out.data(), kdf_out.size(),
                      passphrase.data(), passphrase.size(),
                      salt, ops, static_cast<std::size_t>(mem),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(kdf_out.data(), kdf_out.size());
        throw std::runtime_error("open_seed: argon2id derivation failed (out of memory?)");
    }

    std::vector<std::uint8_t> seed(fb::crypto::kIdentitySeedBytes);
    unsigned long long pt_len = 0;
    // AAD = pre-nonce header for v2; empty for v1 (legacy).
    const std::size_t aad_len = v2 ? static_cast<std::size_t>(nonce - blob.data()) : 0;
    const std::uint8_t* aad   = v2 ? blob.data() : nullptr;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        seed.data(), &pt_len, /*nsec=*/nullptr,
        ct, ct_len, aad, aad_len, nonce, kdf_out.data());
    sodium_memzero(kdf_out.data(), kdf_out.size());
    if (rc != 0) return emscripten::val::null();   // wrong passphrase or tamper
    return to_js_uint8(seed);
}

}  // namespace

// =============================================================================
// WebClient — stateful FinBit client surface for the JS side.
//
// Owns a long-lived Ed25519 identity + per-peer Double Ratchet sessions.
// JS handles protobuf encoding + WebSocket I/O; this class hands JS the
// raw bytes to send (signatures, ciphertexts) and ingests inbound bytes
// (ratchet ciphertext → plaintext).
// =============================================================================

namespace {

class WebClient {
public:
    // Generates a fresh random identity.
    WebClient() {
        ensure_sodium();
        identity_.emplace(fb::crypto::Identity::generate());
        derive_x25519();
    }

    // Reload from a 32-byte Ed25519 seed (the first 32B of a libsodium
    // crypto_sign secret key — same shape JS persisted via identity_seed()).
    // Returns a raw pointer because WebClient holds move-only crypto state
    // (DoubleRatchet / GroupSession maps) and embind can't copy by-value
    // returns. JS owns the resulting object — call .delete() when done.
    static WebClient* from_seed(const emscripten::val& seed_js) {
        ensure_sodium();
        auto bytes = from_js_buffer(seed_js);
        if (bytes.size() != fb::crypto::kIdentitySeedBytes) {
            throw std::runtime_error("from_seed: seed must be 32B");
        }
        std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed{};
        std::memcpy(seed.data(), bytes.data(), seed.size());
        // Private no-init ctor below avoids the wasted Identity::generate()
        // round trip that the default ctor does (and the subsequent
        // derive_x25519 against keys we're about to overwrite).
        auto* w = new WebClient(NoInit{});
        w->identity_.emplace(fb::crypto::Identity::from_seed(seed));
        w->derive_x25519();
        return w;
    }

    emscripten::val identity_pubkey() const {
        std::vector<std::uint8_t> v(identity_->public_key().begin(),
                                     identity_->public_key().end());
        return to_js_uint8(v);
    }
    std::string fingerprint() const { return identity_->fingerprint(); }
    emscripten::val x25519_pub() const {
        std::vector<std::uint8_t> v(x25519_pub_.begin(), x25519_pub_.end());
        return to_js_uint8(v);
    }
    // Returns the 32-byte Ed25519 seed (= first 32B of the secret key) so
    // the JS side can persist + reload it from IndexedDB.
    emscripten::val identity_seed() const {
        const auto sec = identity_->secret_key();
        std::vector<std::uint8_t> v(sec.data(), sec.data() + fb::crypto::kIdentitySeedBytes);
        return to_js_uint8(v);
    }

    emscripten::val sign(const emscripten::val& msg) {
        auto m = from_js_buffer(msg);
        auto sig = identity_->sign(std::span<const std::uint8_t>(m.data(), m.size()));
        return to_js_uint8(std::vector<std::uint8_t>(sig.begin(), sig.end()));
    }

    emscripten::val derive_shared_secret(const emscripten::val& peer_x25519_pub) {
        auto peer = from_js_buffer(peer_x25519_pub);
        if (peer.size() != 32) throw std::runtime_error("peer_x25519 must be 32B");
        std::array<std::uint8_t, 32> dh{};
        if (crypto_scalarmult(dh.data(), x25519_priv_.data(), peer.data()) != 0) {
            throw std::runtime_error("scalarmult low-order");
        }
        constexpr std::string_view info = "FinBit-X3DH-v0";
        auto prk = fb::crypto::hkdf_extract(
            std::span<const std::uint8_t>(),
            std::span<const std::uint8_t>(dh.data(), dh.size()));
        auto out_vec = fb::crypto::hkdf_expand(prk,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(info.data()), info.size()),
            32);
        return to_js_uint8(out_vec);
    }

    emscripten::val ed25519_pub_to_x25519(const emscripten::val& ed_pub) {
        auto e = from_js_buffer(ed_pub);
        if (e.size() != 32) throw std::runtime_error("ed25519 pub must be 32B");
        std::array<std::uint8_t, 32> out{};
        if (crypto_sign_ed25519_pk_to_curve25519(out.data(), e.data()) != 0) {
            throw std::runtime_error("pk_to_curve25519 failed");
        }
        return to_js_uint8(std::vector<std::uint8_t>(out.begin(), out.end()));
    }

    void ratchet_init_alice(const emscripten::val& peer_pubkey,
                             const emscripten::val& shared_secret,
                             const emscripten::val& peer_dh_pub) {
        auto p = from_js_buffer(peer_pubkey);
        auto s = from_js_buffer(shared_secret);
        auto d = from_js_buffer(peer_dh_pub);
        if (s.size() != 32 || d.size() != 32) throw std::runtime_error("32B args required");
        std::array<std::uint8_t, 32> ss{}, pd{};
        std::memcpy(ss.data(), s.data(), 32);
        std::memcpy(pd.data(), d.data(), 32);
        const std::string key(p.begin(), p.end());
        sessions_.erase(key);
        sessions_.emplace(key, fb::crypto::DoubleRatchet::init_alice(
                                   std::span<const std::uint8_t, 32>(ss.data(), 32),
                                   std::span<const std::uint8_t, 32>(pd.data(), 32)));
    }

    void ratchet_init_bob(const emscripten::val& peer_pubkey,
                          const emscripten::val& shared_secret) {
        auto p = from_js_buffer(peer_pubkey);
        auto s = from_js_buffer(shared_secret);
        if (s.size() != 32) throw std::runtime_error("shared_secret must be 32B");
        std::array<std::uint8_t, 32> ss{};
        std::memcpy(ss.data(), s.data(), 32);
        const std::string key(p.begin(), p.end());
        sessions_.erase(key);
        sessions_.emplace(key, fb::crypto::DoubleRatchet::init_bob(
                                   std::span<const std::uint8_t, 32>(ss.data(), 32),
                                   std::span<const std::uint8_t, 32>(x25519_priv_.data(), 32),
                                   std::span<const std::uint8_t, 32>(x25519_pub_.data(), 32)));
    }

    bool has_session(const emscripten::val& peer_pubkey) {
        auto p = from_js_buffer(peer_pubkey);
        return sessions_.count(std::string(p.begin(), p.end())) != 0;
    }

    emscripten::val ratchet_encrypt(const emscripten::val& peer_pubkey,
                                     const emscripten::val& plaintext) {
        auto p = from_js_buffer(peer_pubkey);
        auto it = sessions_.find(std::string(p.begin(), p.end()));
        if (it == sessions_.end()) throw std::runtime_error("no session for peer");
        auto pt = from_js_buffer(plaintext);
        auto ct = it->second.encrypt(
            std::span<const std::uint8_t>(pt.data(), pt.size()), {});
        return to_js_uint8(ct);
    }

    emscripten::val ratchet_decrypt(const emscripten::val& peer_pubkey,
                                     const emscripten::val& ciphertext) {
        auto p = from_js_buffer(peer_pubkey);
        auto it = sessions_.find(std::string(p.begin(), p.end()));
        if (it == sessions_.end()) return emscripten::val::null();
        auto ct = from_js_buffer(ciphertext);
        auto pt = it->second.decrypt(
            std::span<const std::uint8_t>(ct.data(), ct.size()), {});
        if (!pt) return emscripten::val::null();
        return to_js_uint8(*pt);
    }

    // ---- SenderKeys group ops (one GroupSession per channel) -------------
    // create_channel_chain(channel_id) — caller (us) generates a fresh
    // outbound chain. Returns the SenderKeysDistribution blob to deliver
    // to peers via a DM (channel_key payload).
    emscripten::val create_channel_chain(const emscripten::val& channel_id_js) {
        auto cid = from_js_buffer(channel_id_js);
        auto& s = channel_session(cid);
        auto dist = s.create_own_send_chain();
        return to_js_uint8(dist);
    }

    // install_channel_peer_dist — peer sent us their distribution via a DM
    // channel_key payload. Wire it into the channel's GroupSession so we
    // can decrypt their future channel messages.
    void install_channel_peer_dist(const emscripten::val& channel_id_js,
                                    const emscripten::val& peer_pub_js,
                                    const emscripten::val& dist_js) {
        auto cid = from_js_buffer(channel_id_js);
        auto pp  = from_js_buffer(peer_pub_js);
        auto d   = from_js_buffer(dist_js);
        auto& s = channel_session(cid);
        s.install_peer_distribution(
            std::span<const std::uint8_t>(pp.data(), pp.size()),
            std::span<const std::uint8_t>(d.data(), d.size()));
    }

    // channel_encrypt — wraps plaintext into a SenderKeysMessage using OUR
    // own send chain for this channel. Caller wraps the result in an
    // Envelope with channel_group_id = channel_id.
    emscripten::val channel_encrypt(const emscripten::val& channel_id_js,
                                     const emscripten::val& plaintext) {
        auto cid = from_js_buffer(channel_id_js);
        auto& s = channel_session(cid);
        auto pt = from_js_buffer(plaintext);
        auto ct = s.encrypt(std::span<const std::uint8_t>(pt.data(), pt.size()), {});
        return to_js_uint8(ct);
    }

    // channel_decrypt — decrypts an inbound SenderKeysMessage using the
    // peer chain we installed for `sender_pub`. Returns null on missing
    // session / decrypt failure.
    emscripten::val channel_decrypt(const emscripten::val& channel_id_js,
                                     const emscripten::val& sender_pub_js,
                                     const emscripten::val& sender_keys_msg) {
        auto cid = from_js_buffer(channel_id_js);
        auto sp  = from_js_buffer(sender_pub_js);
        auto ct  = from_js_buffer(sender_keys_msg);
        auto it = channels_.find(std::string(cid.begin(), cid.end()));
        if (it == channels_.end()) return emscripten::val::null();
        auto pt = it->second.decrypt(
            std::span<const std::uint8_t>(sp.data(), sp.size()),
            std::span<const std::uint8_t>(ct.data(), ct.size()), {});
        if (!pt) return emscripten::val::null();
        return to_js_uint8(*pt);
    }

private:
    void derive_x25519() {
        const auto sec = identity_->secret_key();
        if (crypto_sign_ed25519_sk_to_curve25519(x25519_priv_.data(), sec.data()) != 0 ||
            crypto_sign_ed25519_pk_to_curve25519(x25519_pub_.data(),
                                                  identity_->public_key().data()) != 0) {
            throw std::runtime_error("ed25519 -> curve25519 failed");
        }
    }

    fb::crypto::GroupSession& channel_session(const std::vector<std::uint8_t>& cid) {
        auto [it, inserted] = channels_.emplace(std::piecewise_construct,
            std::forward_as_tuple(cid.begin(), cid.end()),
            std::forward_as_tuple());
        return it->second;
    }

    struct NoInit {};
    explicit WebClient(NoInit) { ensure_sodium(); }

    std::optional<fb::crypto::Identity> identity_;
    std::array<std::uint8_t, 32> x25519_pub_{};
    std::array<std::uint8_t, 32> x25519_priv_{};
    std::map<std::string, fb::crypto::DoubleRatchet> sessions_;
    std::map<std::string, fb::crypto::GroupSession> channels_;
};

}  // namespace

EMSCRIPTEN_BINDINGS(finbit) {
    emscripten::function("generate_identity_fingerprint", &generate_identity_fingerprint);
    emscripten::function("aead_encrypt", &aead_encrypt);
    emscripten::function("aead_decrypt", &aead_decrypt);
    emscripten::function("aes256gcm_supported", &aes256gcm_supported);
    emscripten::function("xchacha20_encrypt", &xchacha20_encrypt);
    emscripten::function("xchacha20_decrypt", &xchacha20_decrypt);
    emscripten::function("seal_seed",         &seal_seed);
    emscripten::function("seal_seed_with_params", &seal_seed_with_params);
    emscripten::function("open_seed",         &open_seed);

    emscripten::class_<WebClient>("WebClient")
        .constructor<>()
        .class_function("from_seed",        &WebClient::from_seed,
                                            emscripten::allow_raw_pointers())
        .function("identity_pubkey",        &WebClient::identity_pubkey)
        .function("fingerprint",             &WebClient::fingerprint)
        .function("x25519_pub",              &WebClient::x25519_pub)
        .function("identity_seed",           &WebClient::identity_seed)
        .function("sign",                    &WebClient::sign)
        .function("derive_shared_secret",    &WebClient::derive_shared_secret)
        .function("ed25519_pub_to_x25519",   &WebClient::ed25519_pub_to_x25519)
        .function("ratchet_init_alice",      &WebClient::ratchet_init_alice)
        .function("ratchet_init_bob",        &WebClient::ratchet_init_bob)
        .function("has_session",             &WebClient::has_session)
        .function("ratchet_encrypt",         &WebClient::ratchet_encrypt)
        .function("ratchet_decrypt",         &WebClient::ratchet_decrypt)
        .function("create_channel_chain",    &WebClient::create_channel_chain)
        .function("install_channel_peer_dist", &WebClient::install_channel_peer_dist)
        .function("channel_encrypt",         &WebClient::channel_encrypt)
        .function("channel_decrypt",         &WebClient::channel_decrypt);
}
