// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/hkdf.hpp"

#include <sodium.h>

#include <cstring>
#include <stdexcept>

namespace fb::crypto {

HkdfPrk hkdf_extract(std::span<const std::uint8_t> salt,
                     std::span<const std::uint8_t> ikm) {
    // Per RFC 5869 §2.2: if salt is empty, use HashLen zero bytes.
    std::array<std::uint8_t, kHkdfSha256Bytes> zero_salt{};
    const std::uint8_t* key = salt.empty() ? zero_salt.data() : salt.data();
    const std::size_t   key_len = salt.empty() ? zero_salt.size() : salt.size();

    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, ikm.data(), ikm.size());
    HkdfPrk prk{};
    crypto_auth_hmacsha256_final(&st, prk.data());
    return prk;
}

std::vector<std::uint8_t> hkdf_expand(const HkdfPrk& prk,
                                       std::span<const std::uint8_t> info,
                                       std::size_t okm_len) {
    // RFC 5869 §2.3: L <= 255 * HashLen.
    if (okm_len == 0 || okm_len > 255 * kHkdfSha256Bytes) {
        throw std::invalid_argument("hkdf_expand: okm_len out of range (1..8160)");
    }

    std::vector<std::uint8_t> okm(okm_len);
    std::array<std::uint8_t, kHkdfSha256Bytes> t{};   // T(i) — previous block
    std::size_t t_len = 0;                              // 0 for T(0); 32 for T(1..N)
    std::size_t off   = 0;
    std::uint8_t counter = 0;

    while (off < okm_len) {
        ++counter;   // 1-indexed per RFC
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
        if (t_len > 0) crypto_auth_hmacsha256_update(&st, t.data(), t_len);
        crypto_auth_hmacsha256_update(&st, info.data(), info.size());
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t.data());
        t_len = kHkdfSha256Bytes;

        const std::size_t take = std::min(static_cast<std::size_t>(kHkdfSha256Bytes),
                                          okm_len - off);
        std::memcpy(okm.data() + off, t.data(), take);
        off += take;
    }
    return okm;
}

}  // namespace fb::crypto
