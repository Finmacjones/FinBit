// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/handshake/hybrid.hpp"

#include "fb/crypto/hkdf.hpp"
#include "fb/crypto/hybrid_kem.hpp"

#include "envelope.pb.h"
#include "handshake.pb.h"

#include <sodium.h>

#include <cstring>
#include <stdexcept>
#include <string_view>

namespace fb::handshake {

namespace {

// HKDF info string baked into derive_shared_secret. Versioned so a future
// X3DH variant can use a distinct salt without collision risk.
constexpr std::string_view kX3dhInfo = "FinBit-X3DH-v0";

}  // namespace

X25519Pair derive_x25519(const fb::crypto::Identity& id) {
    X25519Pair k;
    auto sec = id.secret_key();
    if (crypto_sign_ed25519_sk_to_curve25519(k.priv.data(), sec.data()) != 0) {
        throw std::runtime_error("ed25519_sk_to_curve25519 failed");
    }
    if (crypto_sign_ed25519_pk_to_curve25519(k.pub.data(), id.public_key().data()) != 0) {
        throw std::runtime_error("ed25519_pk_to_curve25519 failed");
    }
    return k;
}

std::array<std::uint8_t, 32> derive_shared_secret(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_pub) {
    std::array<std::uint8_t, 32> dh{};
    if (crypto_scalarmult(dh.data(), mine.priv.data(), peer_pub.data()) != 0) {
        throw std::runtime_error("scalarmult low-order");
    }
    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(dh.data(), dh.size()));
    auto vec = fb::crypto::hkdf_expand(
        prk,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(kX3dhInfo.data()),
            kX3dhInfo.size()),
        32);
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), vec.data(), 32);
    return out;
}

PqIdentity derive_pq_identity(
    const fb::crypto::Identity& id,
    std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes> seed) {
    PqIdentity p;
    auto pq_seed = fb::crypto::derive_pq_seed_from_identity_seed(seed);
    auto kp = fb::crypto::pq::keygen_ml_kem_768_from_seed(
        std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SeedBytes>(pq_seed));
    p.pub = kp.pub;
    p.sec = kp.sec;
    p.pubkey_sig = id.sign(
        std::span<const std::uint8_t>(p.pub.data(), p.pub.size()));
    return p;
}

HybridSendResult derive_hybrid_send(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    std::span<const std::uint8_t> peer_pq_pub) {
    HybridSendResult out{};
    out.shared = derive_shared_secret(mine, peer_x);
    if (peer_pq_pub.empty()) {
        return out;
    }
    if (peer_pq_pub.size() != fb::crypto::pq::kMlKem768PubBytes) {
        throw std::runtime_error("hybrid_send: pq_pubkey wrong size");
    }
    std::array<std::uint8_t, fb::crypto::pq::kMlKem768PubBytes> peer_arr{};
    std::memcpy(peer_arr.data(), peer_pq_pub.data(), peer_pq_pub.size());
    auto enc = fb::crypto::pq::encap_ml_kem_768(
        std::span<const std::uint8_t, fb::crypto::pq::kMlKem768PubBytes>(peer_arr));
    auto hyb = fb::crypto::hybrid::combine_x25519_mlkem768(
        std::span<const std::uint8_t, 32>(out.shared),
        std::span<const std::uint8_t, 32>(enc.ss));
    std::memcpy(out.shared.data(), hyb.data(), 32);
    out.pq_ct.assign(enc.ct.begin(), enc.ct.end());
    return out;
}

std::array<std::uint8_t, 32> derive_hybrid_recv(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SecBytes> my_pq_sec,
    std::span<const std::uint8_t> pq_ct_bytes) {
    auto ss_x = derive_shared_secret(mine, peer_x);
    if (pq_ct_bytes.empty()) {
        return ss_x;
    }
    if (pq_ct_bytes.size() != fb::crypto::pq::kMlKem768CtBytes) {
        throw std::runtime_error("hybrid_recv: pq_ct wrong size");
    }
    std::array<std::uint8_t, fb::crypto::pq::kMlKem768CtBytes> ct_arr{};
    std::memcpy(ct_arr.data(), pq_ct_bytes.data(), pq_ct_bytes.size());
    auto ss_pq = fb::crypto::pq::decap_ml_kem_768(
        std::span<const std::uint8_t, fb::crypto::pq::kMlKem768CtBytes>(ct_arr),
        my_pq_sec);
    auto hyb = fb::crypto::hybrid::combine_x25519_mlkem768(
        std::span<const std::uint8_t, 32>(ss_x),
        std::span<const std::uint8_t, 32>(ss_pq));
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), hyb.data(), 32);
    return out;
}

HybridSendResult derive_hybrid_send_from_bundle(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    const fb::proto::PreKeyBundle& bundle) {
    std::span<const std::uint8_t> pq_pub(
        reinterpret_cast<const std::uint8_t*>(bundle.pq_pubkey().data()),
        bundle.pq_pubkey().size());
    if (!pq_pub.empty()) {
        if (bundle.identity_pubkey().size() != fb::crypto::kIdentityPubKeyBytes) {
            throw std::runtime_error("hybrid_send_from_bundle: identity_pubkey size");
        }
        if (bundle.pq_pubkey_sig().size() != fb::crypto::kIdentitySigBytes) {
            throw std::runtime_error("hybrid_send_from_bundle: missing pq_pubkey_sig");
        }
        fb::crypto::PubKey id_pub{};
        std::memcpy(id_pub.data(), bundle.identity_pubkey().data(), id_pub.size());
        fb::crypto::Sig sig{};
        std::memcpy(sig.data(), bundle.pq_pubkey_sig().data(), sig.size());
        if (!fb::crypto::Identity::verify(id_pub, pq_pub, sig)) {
            throw std::runtime_error(
                "hybrid_send_from_bundle: pq_pubkey signature invalid — possible MITM");
        }
    }
    return derive_hybrid_send(mine, peer_x, pq_pub);
}

std::array<std::uint8_t, 32> derive_hybrid_recv_from_env(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SecBytes> my_pq_sec,
    const fb::proto::Envelope& env) {
    std::span<const std::uint8_t> ct_span(
        reinterpret_cast<const std::uint8_t*>(env.pq_ct().data()),
        env.pq_ct().size());
    return derive_hybrid_recv(mine, peer_x, my_pq_sec, ct_span);
}

}  // namespace fb::handshake
