// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/shamir.hpp"

#include <sodium.h>

#include <array>
#include <cstring>

namespace fb::crypto::shamir {

namespace {

// GF(256) arithmetic with the AES irreducible polynomial 0x11b.
// Precomputed log + exp tables for fast multiplication. Table generation is
// deterministic; we build at first use under a function-local static so
// there's no static-init order issue with libsodium.

struct GfTables {
    std::array<std::uint8_t, 256> log_table{};
    std::array<std::uint8_t, 256> exp_table{};
    GfTables() {
        std::uint8_t x = 1;
        for (int i = 0; i < 255; ++i) {
            exp_table[static_cast<std::size_t>(i)] = x;
            log_table[x] = static_cast<std::uint8_t>(i);
            // Multiply x by the GF(256) primitive 0x03 (= 0x02 ^ 0x01).
            std::uint16_t y = static_cast<std::uint16_t>(x);
            std::uint16_t y2 = static_cast<std::uint16_t>(y << 1);
            if (y2 & 0x100) y2 = static_cast<std::uint16_t>(y2 ^ 0x11b);
            y = static_cast<std::uint16_t>(y2 ^ y);
            if (y & 0x100) y = static_cast<std::uint16_t>(y ^ 0x11b);
            x = static_cast<std::uint8_t>(y);
        }
        exp_table[255] = exp_table[0];   // wrap so exp(255 + k) lookups stay valid
    }
};

const GfTables& gf() {
    static const GfTables t;
    return t;
}

inline std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) {
    if (a == 0 || b == 0) return 0;
    const auto& T = gf();
    const int la = T.log_table[a];
    const int lb = T.log_table[b];
    return T.exp_table[static_cast<std::size_t>((la + lb) % 255)];
}

inline std::uint8_t gf_div(std::uint8_t a, std::uint8_t b) {
    if (a == 0) return 0;
    if (b == 0) throw ShamirError("GF(256) divide by zero (duplicate x-coords?)");
    const auto& T = gf();
    const int la = T.log_table[a];
    const int lb = T.log_table[b];
    return T.exp_table[static_cast<std::size_t>((la + 255 - lb) % 255)];
}

// Evaluate the polynomial whose coefficients are `coeffs[0]..coeffs[deg]`
// (lowest-degree first; coeffs[0] is the constant term = the secret byte)
// at the GF(256) point `x` using Horner's method.
std::uint8_t gf_eval(const std::vector<std::uint8_t>& coeffs, std::uint8_t x) {
    std::uint8_t acc = coeffs.back();
    for (std::size_t i = coeffs.size() - 1; i-- > 0;) {
        acc = static_cast<std::uint8_t>(gf_mul(acc, x) ^ coeffs[i]);
    }
    return acc;
}

void ensure_sodium() {
    static const int rc = sodium_init();
    if (rc < 0) throw ShamirError("libsodium init failed");
}

}  // namespace

std::vector<std::uint8_t> encode_share(const Share& s) {
    if (s.x == 0 || s.y.empty()) {
        throw ShamirError("encode_share: invalid share (x must be 1..255, y non-empty)");
    }
    std::vector<std::uint8_t> out;
    out.reserve(1 + s.y.size());
    out.push_back(s.x);
    out.insert(out.end(), s.y.begin(), s.y.end());
    return out;
}

Share decode_share(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 2) {
        throw ShamirError("decode_share: too short (need at least 1 x-byte + 1 y-byte)");
    }
    if (bytes[0] == 0) {
        throw ShamirError("decode_share: x-coord 0 is reserved for the secret");
    }
    Share s;
    s.x = bytes[0];
    s.y.assign(bytes.begin() + 1, bytes.end());
    return s;
}

std::vector<Share> split(std::span<const std::uint8_t> secret,
                          std::uint8_t threshold,
                          std::uint8_t total) {
    if (secret.empty()) {
        throw ShamirError("split: empty secret");
    }
    if (threshold == 0 || total == 0 || threshold > total) {
        throw ShamirError("split: bad threshold/total (require 1 <= M <= N <= 255)");
    }
    ensure_sodium();

    // For each secret byte build a fresh degree-(M-1) polynomial whose
    // constant term IS the secret byte; evaluate at x = 1..N.
    std::vector<Share> shares(total);
    for (std::uint8_t i = 0; i < total; ++i) {
        shares[i].x = static_cast<std::uint8_t>(i + 1);   // 1..N
        shares[i].y.resize(secret.size());
    }

    std::vector<std::uint8_t> coeffs(threshold);
    for (std::size_t b = 0; b < secret.size(); ++b) {
        coeffs[0] = secret[b];                              // f(0) = secret byte
        if (threshold > 1) {
            randombytes_buf(coeffs.data() + 1, threshold - 1);
        }
        for (std::uint8_t i = 0; i < total; ++i) {
            shares[i].y[b] = gf_eval(coeffs, shares[i].x);
        }
    }
    return shares;
}

std::vector<std::uint8_t> combine(std::span<const Share> shares) {
    if (shares.empty()) {
        throw ShamirError("combine: no shares");
    }
    const std::size_t L = shares.front().y.size();
    if (L == 0) {
        throw ShamirError("combine: zero-length share payload");
    }
    // All shares must agree on payload length and have unique nonzero x.
    for (std::size_t i = 0; i < shares.size(); ++i) {
        if (shares[i].x == 0) {
            throw ShamirError("combine: share x=0 is invalid");
        }
        if (shares[i].y.size() != L) {
            throw ShamirError("combine: share length mismatch");
        }
        for (std::size_t j = i + 1; j < shares.size(); ++j) {
            if (shares[i].x == shares[j].x) {
                throw ShamirError("combine: duplicate x-coordinate");
            }
        }
    }

    // Lagrange interpolation at x = 0, byte-wise.
    // f(0) = sum_i  y_i * prod_{j != i}  (-x_j) / (x_i - x_j)
    // In GF(2^k), additive inverse equals the element itself; subtraction is XOR.
    std::vector<std::uint8_t> secret(L, 0);
    for (std::size_t b = 0; b < L; ++b) {
        std::uint8_t acc = 0;
        for (std::size_t i = 0; i < shares.size(); ++i) {
            std::uint8_t num = 1, den = 1;
            for (std::size_t j = 0; j < shares.size(); ++j) {
                if (i == j) continue;
                num = gf_mul(num, shares[j].x);                  // ∏ x_j
                den = gf_mul(den, static_cast<std::uint8_t>(shares[i].x ^ shares[j].x));
            }
            const std::uint8_t basis = gf_div(num, den);
            acc = static_cast<std::uint8_t>(acc ^ gf_mul(shares[i].y[b], basis));
        }
        secret[b] = acc;
    }
    return secret;
}

}  // namespace fb::crypto::shamir
