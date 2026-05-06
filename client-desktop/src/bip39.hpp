// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Minimal BIP39 encode/decode for the 32-byte FinBit identity seed.
//
//   32-byte seed (256 bits) + SHA-256(seed)[0..7] (8 checksum bits)
//                = 264 bits = 24 × 11-bit chunks
//   Each 11-bit chunk indexes into the 2048-word English wordlist.
//
// Wire-compatible with client-web/ui/bip39.js — a phrase generated on
// either side decodes to the same 32-byte seed on the other.

#include <QString>

#include <array>
#include <cstdint>
#include <optional>

#include "identity_vault.hpp"   // for fb::desktop::Seed

namespace fb::desktop {

// 32-byte seed → 24-word phrase (space-separated, lowercase).
[[nodiscard]] QString seed_to_phrase(const Seed& seed);

// 24-word phrase → 32-byte seed. Returns std::nullopt on:
//   * not exactly 24 whitespace-separated tokens
//   * unknown word
//   * checksum mismatch (catches typos)
[[nodiscard]] std::optional<Seed> phrase_to_seed(const QString& phrase);

}  // namespace fb::desktop
