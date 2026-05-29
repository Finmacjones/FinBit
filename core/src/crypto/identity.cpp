// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/identity.hpp"

#include "fb/crypto/hkdf.hpp"

#include <sodium.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace fb::crypto {
namespace {

// Crockford base32 alphabet (no I, L, O, U) — friendlier than RFC 4648 for
// human transcription. Exactly 32 chars so a 5-bit index never reads OOB.
constexpr std::string_view kBase32Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static_assert(kBase32Alphabet.size() == 32, "must cover all 5-bit values");

void ensure_sodium() {
    static const int rc = sodium_init();
    if (rc < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

std::uint8_t* alloc_locked_seckey() {
    auto* p = static_cast<std::uint8_t*>(sodium_malloc(kIdentitySecKeyBytes));
    if (!p) {
        throw std::bad_alloc();
    }
    return p;
}

}  // namespace

Identity::Identity(Identity&& other) noexcept
    : pub_(other.pub_), sec_locked_(other.sec_locked_) {
    other.sec_locked_ = nullptr;
    other.pub_.fill(0);
}

Identity& Identity::operator=(Identity&& other) noexcept {
    if (this != &other) {
        if (sec_locked_) {
            sodium_free(sec_locked_);
        }
        pub_              = other.pub_;
        sec_locked_       = other.sec_locked_;
        other.sec_locked_ = nullptr;
        other.pub_.fill(0);
    }
    return *this;
}

Identity::~Identity() {
    if (sec_locked_) {
        sodium_free(sec_locked_);
        sec_locked_ = nullptr;
    }
}

std::span<const std::uint8_t, kIdentitySecKeyBytes> Identity::secret_key() const noexcept {
    return std::span<const std::uint8_t, kIdentitySecKeyBytes>(sec_locked_, kIdentitySecKeyBytes);
}

Identity Identity::generate() {
    ensure_sodium();
    Identity id;
    id.sec_locked_ = alloc_locked_seckey();
    if (crypto_sign_keypair(id.pub_.data(), id.sec_locked_) != 0) {
        sodium_free(id.sec_locked_);
        id.sec_locked_ = nullptr;
        throw std::runtime_error("crypto_sign_keypair failed");
    }
    return id;
}

Identity Identity::from_seed(std::span<const std::uint8_t, kIdentitySeedBytes> seed) {
    ensure_sodium();
    Identity id;
    id.sec_locked_ = alloc_locked_seckey();
    if (crypto_sign_seed_keypair(id.pub_.data(), id.sec_locked_, seed.data()) != 0) {
        sodium_free(id.sec_locked_);
        id.sec_locked_ = nullptr;
        throw std::runtime_error("crypto_sign_seed_keypair failed");
    }
    return id;
}

Sig Identity::sign(std::span<const std::uint8_t> message) const {
    if (!sec_locked_) {
        throw std::logic_error("Identity::sign on moved-from object");
    }
    Sig sig{};
    unsigned long long siglen = 0;
    if (crypto_sign_detached(sig.data(), &siglen, message.data(), message.size(),
                             sec_locked_) != 0) {
        throw std::runtime_error("crypto_sign_detached failed");
    }
    if (siglen != kIdentitySigBytes) {
        throw std::runtime_error("unexpected Ed25519 signature length");
    }
    return sig;
}

bool Identity::verify(const PubKey& pubkey, std::span<const std::uint8_t> message,
                      const Sig& signature) noexcept {
    return crypto_sign_verify_detached(signature.data(), message.data(), message.size(),
                                       pubkey.data()) == 0;
}

std::string Identity::fingerprint(const PubKey& pubkey) {
    ensure_sodium();
    // BLAKE2b-160 (20 bytes) of the public key; encode first 6 bytes as 10
    // base32 chars, group as XXXXX-XXXXX.
    std::array<std::uint8_t, 20> hash{};
    if (crypto_generichash(hash.data(), hash.size(), pubkey.data(), pubkey.size(), nullptr, 0) !=
        0) {
        throw std::runtime_error("crypto_generichash failed");
    }
    // 6 bytes = 48 bits = 9.6 base32 chars; we take 10 chars (50 bits) by
    // pulling from a 7-byte window.
    std::array<std::uint8_t, 7> window{};
    for (std::size_t i = 0; i < window.size(); ++i) {
        window[i] = hash[i];
    }
    std::string out;
    out.reserve(11);
    std::uint64_t bits = 0;
    for (std::size_t i = 0; i < 5; ++i) {
        bits = (bits << 8) | window[i];
    }
    for (int shift = 45; shift >= 0; shift -= 5) {
        if (out.size() == 5) out.push_back('-');
        const std::size_t idx = static_cast<std::size_t>((bits >> shift) & 0x1F);
        out.push_back(kBase32Alphabet[idx]);
    }
    return out;
}

std::string pubkey_to_base64(const PubKey& pubkey) {
    ensure_sodium();
    const std::size_t enc_len =
        sodium_base64_ENCODED_LEN(pubkey.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(enc_len, '\0');
    sodium_bin2base64(out.data(), out.size(), pubkey.data(), pubkey.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    // sodium_bin2base64 writes a trailing NUL inside the buffer; trim it.
    if (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}

bool pubkey_from_base64(std::string_view encoded, PubKey& out) noexcept {
    ensure_sodium();
    std::size_t bin_len = 0;
    const int rc = sodium_base642bin(out.data(), out.size(), encoded.data(), encoded.size(),
                                     /*ignore=*/nullptr, &bin_len, /*end=*/nullptr,
                                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return rc == 0 && bin_len == out.size();
}

std::string safety_number(const PubKey& a, const PubKey& b) {
    ensure_sodium();
    // Bytewise lex-sort the two pubkeys so safety_number(a, b) ==
    // safety_number(b, a) — both peers compute the same number.
    std::array<std::uint8_t, kIdentityPubKeyBytes * 2> joined{};
    const bool a_first =
        std::memcmp(a.data(), b.data(), kIdentityPubKeyBytes) <= 0;
    const PubKey& lo = a_first ? a : b;
    const PubKey& hi = a_first ? b : a;
    std::memcpy(joined.data(),                        lo.data(), kIdentityPubKeyBytes);
    std::memcpy(joined.data() + kIdentityPubKeyBytes, hi.data(), kIdentityPubKeyBytes);

    // BLAKE2b-256 → 32 bytes.
    std::array<std::uint8_t, 32> h{};
    crypto_generichash(h.data(), h.size(), joined.data(), joined.size(),
                       nullptr, 0);

    // 30 of the 32 hash bytes → 12 groups of 5 decimal digits = 60 digits
    // total (~199 bits of MITM-detection entropy). Each 5-byte chunk →
    // two 5-digit groups via (u40 / 10^5) % 10^5 and u40 % 10^5.
    std::string out;
    out.reserve(60 + 11);
    for (std::size_t chunk = 0; chunk < 6; ++chunk) {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 5; ++i) {
            v = (v << 8) | h[chunk * 5 + i];
        }
        const std::uint32_t hi5 = static_cast<std::uint32_t>(
            (v / 100000ULL) % 100000ULL);
        const std::uint32_t lo5 = static_cast<std::uint32_t>(v % 100000ULL);
        char buf[6];
        std::snprintf(buf, sizeof(buf), "%05u", hi5);
        if (!out.empty()) out.push_back(' ');
        out.append(buf, 5);
        std::snprintf(buf, sizeof(buf), "%05u", lo5);
        out.push_back(' ');
        out.append(buf, 5);
    }
    return out;
}

std::array<std::uint8_t, 64> derive_pq_seed_from_identity_seed(
    std::span<const std::uint8_t, kIdentitySeedBytes> seed) {
    constexpr char kInfo[] = "FinBit-PQ-seed-v1";
    auto prk = hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(seed.data(), seed.size()));
    auto okm = hkdf_expand(
        prk,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(kInfo), sizeof(kInfo) - 1),
        64);
    std::array<std::uint8_t, 64> out{};
    std::memcpy(out.data(), okm.data(), 64);
    return out;
}

std::array<std::uint8_t, 32> derive_pq_sig_seed_from_identity_seed(
    std::span<const std::uint8_t, kIdentitySeedBytes> seed) {
    constexpr char kInfo[] = "FinBit-PQSIG-seed-v1";
    auto prk = hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(seed.data(), seed.size()));
    auto okm = hkdf_expand(
        prk,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(kInfo), sizeof(kInfo) - 1),
        32);
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), okm.data(), 32);
    return out;
}

}  // namespace fb::crypto
