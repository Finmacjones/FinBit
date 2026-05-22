// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/room_keys.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>

#include "fb/media/sframe.hpp"

using fb::media::RoomKeyRegistry;
using fb::media::derive_room_sframe_key;

namespace {

std::array<std::uint8_t, 32> k32(std::uint8_t fill) {
    std::array<std::uint8_t, 32> a{};
    a.fill(fill);
    return a;
}
std::string sbytes(const std::array<std::uint8_t, 32>& a) {
    return std::string(reinterpret_cast<const char*>(a.data()), a.size());
}
std::array<std::uint8_t, 32> derive(const std::array<std::uint8_t, 32>& secret,
                                    const std::array<std::uint8_t, 32>& who,
                                    std::uint32_t epoch) {
    return derive_room_sframe_key(
        std::span<const std::uint8_t, 32>(secret.data(), 32),
        std::span<const std::uint8_t>(who.data(), who.size()), epoch);
}

}  // namespace

TEST(RoomKeyRegistry, EmptyBeforeSecret) {
    RoomKeyRegistry reg(k32(0x01));
    EXPECT_FALSE(reg.has_secret());
    EXPECT_EQ(reg.epoch(), 0u);
    EXPECT_FALSE(reg.seal_key().has_value());
    EXPECT_FALSE(reg.open_key(sbytes(k32(0x02)), 1).has_value());
}

TEST(RoomKeyRegistry, SealKeyMatchesDerive) {
    auto me = k32(0x11);
    auto secret = k32(0xA1);
    RoomKeyRegistry reg(me);
    reg.set_secret(std::span<const std::uint8_t, 32>(secret.data(), 32), 1);

    ASSERT_TRUE(reg.has_secret());
    EXPECT_EQ(reg.epoch(), 1u);
    auto sk = reg.seal_key();
    ASSERT_TRUE(sk.has_value());
    EXPECT_EQ(sk->epoch, 1u);
    EXPECT_EQ(sk->key, derive(secret, me, 1));   // K_self
}

TEST(RoomKeyRegistry, OpenKeyMatchesDeriveIsolatesSendersAndCaches) {
    auto me = k32(0x11);
    auto secret = k32(0xA1);
    auto bob = k32(0xB2);
    auto carol = k32(0xC3);
    RoomKeyRegistry reg(me);
    reg.set_secret(std::span<const std::uint8_t, 32>(secret.data(), 32), 1);

    auto kb = reg.open_key(sbytes(bob), 1);
    ASSERT_TRUE(kb.has_value());
    EXPECT_EQ(*kb, derive(secret, bob, 1));         // K_bob

    auto kc = reg.open_key(sbytes(carol), 1);
    ASSERT_TRUE(kc.has_value());
    EXPECT_NE(*kc, *kb);                             // per-sender isolation

    EXPECT_EQ(reg.open_key(sbytes(bob), 1), kb);     // deterministic / cached
}

TEST(RoomKeyRegistry, UnknownEpochDropped) {
    auto secret = k32(0xA1);
    RoomKeyRegistry reg(k32(0x11));
    reg.set_secret(std::span<const std::uint8_t, 32>(secret.data(), 32), 4);

    EXPECT_TRUE(reg.open_key(sbytes(k32(0xB2)), 4).has_value());
    EXPECT_FALSE(reg.open_key(sbytes(k32(0xB2)), 3).has_value());  // older
    EXPECT_FALSE(reg.open_key(sbytes(k32(0xB2)), 5).has_value());  // future
}

TEST(RoomKeyRegistry, StaleOrDuplicateEpochIgnored) {
    auto me = k32(0x11);
    auto a = k32(0xA1), c = k32(0xCC), d = k32(0xDD);
    RoomKeyRegistry reg(me);
    reg.set_secret(std::span<const std::uint8_t, 32>(a.data(), 32), 5);
    auto sk0 = reg.seal_key();

    reg.set_secret(std::span<const std::uint8_t, 32>(c.data(), 32), 5);  // dup epoch
    EXPECT_EQ(reg.epoch(), 5u);
    EXPECT_EQ(reg.seal_key()->key, sk0->key);       // unchanged (c ignored)

    reg.set_secret(std::span<const std::uint8_t, 32>(d.data(), 32), 3);  // stale
    EXPECT_EQ(reg.epoch(), 5u);
    EXPECT_EQ(reg.seal_key()->key, sk0->key);       // still a@5
}

TEST(RoomKeyRegistry, SealKeyRotatesOnNewEpoch) {
    auto me = k32(0x11);
    auto a = k32(0xA1), b = k32(0xB1);
    RoomKeyRegistry reg(me);
    reg.set_secret(std::span<const std::uint8_t, 32>(a.data(), 32), 1);
    auto sk1 = reg.seal_key();
    reg.set_secret(std::span<const std::uint8_t, 32>(b.data(), 32), 2);
    auto sk2 = reg.seal_key();

    ASSERT_TRUE(sk1 && sk2);
    EXPECT_EQ(sk2->epoch, 2u);
    EXPECT_NE(sk2->key, sk1->key);
    EXPECT_EQ(sk2->key, derive(b, me, 2));
}

TEST(RoomKeyRegistry, RotationGraceWindowOpensPrevThenDrops) {
    auto me = k32(0x11);
    auto a = k32(0xA1), b = k32(0xB1), bob = k32(0xB2);
    auto now = std::make_shared<std::chrono::steady_clock::time_point>(
        std::chrono::steady_clock::now());
    RoomKeyRegistry reg(me, std::chrono::milliseconds(100),
                        [now] { return *now; });

    reg.set_secret(std::span<const std::uint8_t, 32>(a.data(), 32), 1);
    reg.set_secret(std::span<const std::uint8_t, 32>(b.data(), 32), 2);  // rotate

    // New epoch opens from B; old epoch still opens from A inside the window.
    EXPECT_EQ(reg.open_key(sbytes(bob), 2), derive(b, bob, 2));
    EXPECT_EQ(reg.open_key(sbytes(bob), 1), derive(a, bob, 1));

    *now += std::chrono::milliseconds(250);   // past the 100 ms grace
    EXPECT_FALSE(reg.open_key(sbytes(k32(0xEE)), 1).has_value());  // prev expired
    EXPECT_EQ(reg.open_key(sbytes(bob), 2), derive(b, bob, 2));    // current fine
}

TEST(RoomKeyRegistry, DeterministicAcrossMembers) {
    // Two members' registries (same identity input here) derive identical
    // keys from the same secret — the cross-member agreement the forwarded
    // room relies on, surfaced at the registry layer.
    auto me = k32(0x11);
    auto secret = k32(0xA1);
    auto bob = k32(0xB2);
    RoomKeyRegistry r1(me), r2(me);
    r1.set_secret(std::span<const std::uint8_t, 32>(secret.data(), 32), 7);
    r2.set_secret(std::span<const std::uint8_t, 32>(secret.data(), 32), 7);

    EXPECT_EQ(r1.seal_key()->key, r2.seal_key()->key);
    EXPECT_EQ(r1.open_key(sbytes(bob), 7), r2.open_key(sbytes(bob), 7));
}
