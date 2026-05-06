// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/mesh/bridge.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {
std::vector<std::uint8_t> bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
std::span<const std::uint8_t> span_of(const std::vector<std::uint8_t>& v) {
    return std::span<const std::uint8_t>(v.data(), v.size());
}
}  // namespace

TEST(MeshCompression, RoundTripChat) {
    const auto pt = bytes(
        "hey everyone, anyone around? heading to the meeting in the channel "
        "soon — let me know if you need the link. thanks");
    auto comp = fb::mesh::compress_for_mesh(span_of(pt));
    EXPECT_LT(comp.size(), pt.size())
        << "brotli should shrink chat-heavy text below original";
    auto decomp = fb::mesh::decompress_from_mesh(span_of(comp));
    EXPECT_EQ(decomp, pt);
}

TEST(MeshCompression, EmptyInputProducesEmpty) {
    auto comp = fb::mesh::compress_for_mesh({});
    EXPECT_TRUE(comp.empty());
    auto decomp = fb::mesh::decompress_from_mesh({});
    EXPECT_TRUE(decomp.empty());
}

TEST(MeshCompression, FitsInSingleLoraFrame) {
    // A typical chat line should comfortably fit inside a single ~200-byte
    // mesh frame after brotli + the static dict. This is the headline
    // value-prop for the mesh bridge.
    const auto pt = bytes("FinBit channel msg — see you at the meeting");
    auto comp = fb::mesh::compress_for_mesh(span_of(pt));
    EXPECT_LE(comp.size(), 200u)
        << "compressed = " << comp.size() << " bytes, plaintext = " << pt.size();
}
