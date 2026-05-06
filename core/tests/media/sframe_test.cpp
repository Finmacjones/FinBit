// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/media/sframe.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {
std::array<std::uint8_t, 32> demo_base_key() {
    std::array<std::uint8_t, 32> k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(0xA0 ^ i);
    return k;
}
std::vector<std::uint8_t> bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
}  // namespace

TEST(SFrame, RoundTripSucceeds) {
    auto k = demo_base_key();
    auto pt = bytes("a frame of audio or video");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 42,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto recovered = fb::media::sframe_open_v1(
        std::span<const std::uint8_t, 32>(k),
        std::span<const std::uint8_t>(sealed.data(), sealed.size()));
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(*recovered, pt);
}

TEST(SFrame, DifferentCountersProduceDifferentCiphertext) {
    auto k = demo_base_key();
    auto pt = bytes("same plaintext");
    auto a = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 1,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto b = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 2,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_NE(a, b);
}

TEST(SFrame, DifferentEpochsProduceDifferentCiphertext) {
    auto k = demo_base_key();
    auto pt = bytes("same plaintext");
    auto a = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 99,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto b = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 2, 99,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_NE(a, b);
}

TEST(SFrame, WrongKeyFailsOpen) {
    auto k1 = demo_base_key();
    std::array<std::uint8_t, 32> k2{};
    for (std::size_t i = 0; i < k2.size(); ++i) k2[i] = 0x77;
    auto pt = bytes("oof");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k1), 0, 0,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(k2),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

TEST(SFrame, TamperedHeaderRejected) {
    auto k = demo_base_key();
    auto pt = bytes("payload");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 5,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    sealed[0] ^= 0x01;  // flip a header bit (epoch high byte)
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(k),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

TEST(SFrame, TamperedCiphertextRejected) {
    auto k = demo_base_key();
    auto pt = bytes("payload");
    auto sealed = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 1, 5,
                                            std::span<const std::uint8_t>(pt.data(), pt.size()));
    sealed.back() ^= 0x01;
    EXPECT_FALSE(fb::media::sframe_open_v1(
                     std::span<const std::uint8_t, 32>(k),
                     std::span<const std::uint8_t>(sealed.data(), sealed.size()))
                     .has_value());
}

TEST(SFrame, DeterministicSealForSameInputs) {
    auto k = demo_base_key();
    auto pt = bytes("same input -> same output");
    auto a = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 7, 12345,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    auto b = fb::media::sframe_seal_v1(std::span<const std::uint8_t, 32>(k), 7, 12345,
                                       std::span<const std::uint8_t>(pt.data(), pt.size()));
    EXPECT_EQ(a, b) << "SFrame seal must be deterministic for fixed (key, epoch, counter)";
}
