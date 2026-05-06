// SPDX-License-Identifier: AGPL-3.0-or-later
#include "bip39.hpp"

#include <sodium.h>     // crypto_hash_sha256

#include <QHash>
#include <QRegularExpression>
#include <QStringList>

#include <cstring>

#include "bip39_wordlist.hpp"

namespace fb::desktop {

namespace {

// Lazily-built reverse lookup: word → index. Avoids a const Map<> with a
// 2048-entry initializer; we only build it once on first phrase_to_seed.
const QHash<QString, std::uint16_t>& word_index() {
    static const QHash<QString, std::uint16_t> kIndex = []() {
        QHash<QString, std::uint16_t> m;
        m.reserve(2048);
        for (std::uint16_t i = 0; i < 2048; ++i) {
            m.insert(QString::fromUtf8(kBip39En[i]), i);
        }
        return m;
    }();
    return kIndex;
}

}  // namespace

QString seed_to_phrase(const Seed& seed) {
    // Build a 33-byte "entropy + checksum" buffer:
    // [seed(32)][SHA-256(seed)[0]] (top 8 bits of the digest = checksum)
    std::array<std::uint8_t, 32> digest{};
    crypto_hash_sha256(digest.data(), seed.data(), seed.size());

    std::array<std::uint8_t, 33> ent{};
    std::memcpy(ent.data(), seed.data(), 32);
    ent[32] = digest[0];

    // Walk 264 bits in 11-bit chunks (24 of them).
    QStringList words;
    words.reserve(24);
    for (int i = 0; i < 24; ++i) {
        std::uint16_t v = 0;
        for (int b = 0; b < 11; ++b) {
            const int bit  = i * 11 + b;
            const int byte = bit >> 3;
            const int off  = 7 - (bit & 7);
            v = static_cast<std::uint16_t>((v << 1) | ((ent[byte] >> off) & 1));
        }
        words.append(QString::fromUtf8(kBip39En[v]));
    }
    return words.join(' ');
}

std::optional<Seed> phrase_to_seed(const QString& phrase) {
    QStringList tokens = phrase
        .normalized(QString::NormalizationForm_KD)
        .toLower()
        .trimmed()
        .split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (tokens.size() != 24) return std::nullopt;

    const auto& idx = word_index();
    std::array<std::uint8_t, 33> ent{};
    int bitpos = 0;
    for (const QString& w : tokens) {
        const auto it = idx.constFind(w);
        if (it == idx.constEnd()) return std::nullopt;
        std::uint16_t v = *it;
        for (int b = 10; b >= 0; --b) {
            const int byte = bitpos >> 3;
            const int off  = 7 - (bitpos & 7);
            ent[byte] = static_cast<std::uint8_t>(
                ent[byte] | (((v >> b) & 1) << off));
            bitpos++;
        }
    }
    Seed seed{};
    std::memcpy(seed.data(), ent.data(), 32);

    std::array<std::uint8_t, 32> digest{};
    crypto_hash_sha256(digest.data(), seed.data(), seed.size());
    if (digest[0] != ent[32]) return std::nullopt;   // checksum mismatch
    return seed;
}

}  // namespace fb::desktop
