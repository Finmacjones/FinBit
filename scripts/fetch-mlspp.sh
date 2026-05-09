#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# =============================================================================
# fetch-mlspp.sh — vendor mlspp under third_party/ for the MLS feature.
#
# Cisco's mlspp implements RFC 9420 (MLS — Messaging Layer Security). It's
# not in most distro repos, isn't a header-only dep, and we need a stable
# pin rather than whatever HEAD happens to be on the day someone builds.
#
# Usage:
#   scripts/fetch-mlspp.sh                 # clone if missing, no-op otherwise
#   scripts/fetch-mlspp.sh --force         # wipe and re-clone
#   scripts/fetch-mlspp.sh --pin <ref>     # check out a specific commit/tag
#
# After this, configure with -DFB_FEATURE_MLS=ON to enable the MLS path.
# Vanilla builds (no flag) still work without mlspp on disk — the
# mls_facade.cpp stub branch keeps the codebase compiling and SenderKeys
# stays the channel cipher.
# =============================================================================

set -euo pipefail

REPO_URL="https://github.com/cisco/mlspp.git"
DEFAULT_PIN="main"      # mlspp doesn't tag releases; main is the upstream

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../third_party/mlspp"

force=0
pin="${DEFAULT_PIN}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --force) force=1; shift ;;
        --pin)   pin="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ "${force}" = "1" ] && [ -d "${TARGET}" ]; then
    echo "== removing existing ${TARGET}"
    rm -rf "${TARGET}"
fi

if [ -d "${TARGET}/.git" ] || [ -d "${TARGET}/lib/hpke" ]; then
    echo "== mlspp already present at ${TARGET} (--force to re-fetch)"
    exit 0
fi

echo "== cloning mlspp (pin=${pin}) into ${TARGET}"
mkdir -p "$(dirname "${TARGET}")"
git clone --depth 1 --branch "${pin}" "${REPO_URL}" "${TARGET}"

echo "== removing mlspp's .git so the vendored tree doesn't appear as a submodule"
rm -rf "${TARGET}/.git"

cat <<EOF

mlspp vendored under third_party/mlspp.
Configure with:
  cmake -S . -B build-mls -DFB_FEATURE_MLS=ON
  cmake --build build-mls -j

Tests covering the MLS facade live in core/tests/crypto/mls_facade_test.cpp.
EOF
