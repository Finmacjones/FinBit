// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/mls_facade.hpp"

#include <stdexcept>

// =============================================================================
// PHASE 0 STUB. See mls_facade.hpp.
//
// Wiring plan when picking this up in Phase 1:
//   1. add `find_package(mlspp CONFIG REQUIRED)` to core/CMakeLists.txt
//      under FB_FEATURE_MLS gating
//   2. include <mls/state.h>, <mls/credential.h> here
//   3. wrap mls::State in a private impl class behind MlsGroup
//   4. mls::State::commit/process_commit map directly to apply_commit + the
//      add_member/remove_member output
//   5. import IETF MLS interop test vectors into core/tests/crypto/
//      mls_interop_test.cpp (mlspp ships them in test/data)
// =============================================================================

namespace fb::crypto {
namespace {
[[noreturn]] void unimpl(const char* what) {
    throw std::runtime_error(std::string("MlsGroup: ") + what +
                             " not implemented (Phase 1 — needs mlspp dep)");
}
}  // namespace

std::unique_ptr<MlsGroup> MlsGroup::create(std::span<const std::uint8_t, 32>,
                                            std::span<const std::uint8_t, 32>) {
    unimpl("create");
}

std::unique_ptr<MlsGroup> MlsGroup::from_blob(std::span<const std::uint8_t>) {
    unimpl("from_blob");
}

}  // namespace fb::crypto
