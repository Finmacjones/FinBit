// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/aead.hpp"

#include <sodium.h>

#include <stdexcept>
#include <string>

namespace fb::crypto {
namespace {

void ensure_sodium() {
    static const int rc = sodium_init();
    if (rc < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

[[noreturn]] void unsupported_alg(AeadAlg alg) {
    throw std::invalid_argument("unsupported AEAD algorithm: " +
                                std::to_string(static_cast<std::uint32_t>(alg)));
}

}  // namespace

bool aes256gcm_hw_available() noexcept {
    // libsodium docs: must be called AFTER sodium_init(). The init guard
    // throws on failure; we swallow it here to keep this function noexcept and
    // return false on the (vanishingly rare) init failure.
    try {
        ensure_sodium();
    } catch (...) {
        return false;
    }
    return crypto_aead_aes256gcm_is_available() == 1;
}

AeadKey random_key() {
    ensure_sodium();
    AeadKey k{};
    randombytes_buf(k.data(), k.size());
    return k;
}

AeadNonce random_nonce() {
    ensure_sodium();
    AeadNonce n{};
    randombytes_buf(n.data(), n.size());
    return n;
}

std::vector<std::uint8_t> aead_encrypt(AeadAlg alg, const AeadKey& key, const AeadNonce& nonce,
                                       std::span<const std::uint8_t> plaintext,
                                       std::span<const std::uint8_t> aad) {
    ensure_sodium();
    if (alg != AeadAlg::kAes256Gcm) {
        unsupported_alg(alg);
    }
    if (!aes256gcm_hw_available()) {
        throw std::runtime_error(
            "AES-256-GCM hardware acceleration unavailable on this CPU; "
            "XChaCha20-Poly1305 fallback not yet implemented");
    }

    std::vector<std::uint8_t> out(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long out_len = 0;
    const int rc = crypto_aead_aes256gcm_encrypt(
        out.data(), &out_len, plaintext.data(), plaintext.size(), aad.data(), aad.size(),
        /*nsec=*/nullptr, nonce.data(), key.data());
    if (rc != 0) {
        throw std::runtime_error("crypto_aead_aes256gcm_encrypt failed");
    }
    out.resize(out_len);
    return out;
}

std::optional<std::vector<std::uint8_t>> aead_decrypt(AeadAlg alg, const AeadKey& key,
                                                      const AeadNonce& nonce,
                                                      std::span<const std::uint8_t> ct,
                                                      std::span<const std::uint8_t> aad) {
    ensure_sodium();
    if (alg != AeadAlg::kAes256Gcm) {
        unsupported_alg(alg);
    }
    if (!aes256gcm_hw_available()) {
        throw std::runtime_error("AES-256-GCM hardware acceleration unavailable");
    }
    if (ct.size() < crypto_aead_aes256gcm_ABYTES) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> out(ct.size() - crypto_aead_aes256gcm_ABYTES);
    unsigned long long out_len = 0;
    const int rc = crypto_aead_aes256gcm_decrypt(
        out.data(), &out_len, /*nsec=*/nullptr, ct.data(), ct.size(), aad.data(), aad.size(),
        nonce.data(), key.data());
    if (rc != 0) {
        return std::nullopt;
    }
    out.resize(out_len);
    return out;
}

XChaChaNonce random_xchacha_nonce() {
    ensure_sodium();
    XChaChaNonce n{};
    randombytes_buf(n.data(), n.size());
    return n;
}

std::vector<std::uint8_t> xchacha20_encrypt(const AeadKey& key, const XChaChaNonce& nonce,
                                             std::span<const std::uint8_t> plaintext,
                                             std::span<const std::uint8_t> aad) {
    ensure_sodium();
    std::vector<std::uint8_t> out(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long out_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.data(), &out_len, plaintext.data(), plaintext.size(), aad.data(), aad.size(),
            /*nsec=*/nullptr, nonce.data(), key.data()) != 0) {
        throw std::runtime_error("crypto_aead_xchacha20poly1305_ietf_encrypt failed");
    }
    out.resize(out_len);
    return out;
}

std::optional<std::vector<std::uint8_t>> xchacha20_decrypt(
    const AeadKey& key, const XChaChaNonce& nonce, std::span<const std::uint8_t> ct,
    std::span<const std::uint8_t> aad) {
    ensure_sodium();
    if (ct.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) return std::nullopt;
    std::vector<std::uint8_t> out(ct.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long out_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.data(), &out_len, /*nsec=*/nullptr, ct.data(), ct.size(), aad.data(), aad.size(),
        nonce.data(), key.data());
    if (rc != 0) return std::nullopt;
    out.resize(out_len);
    return out;
}

}  // namespace fb::crypto
