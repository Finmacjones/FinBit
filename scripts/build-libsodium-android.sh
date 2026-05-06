#!/usr/bin/env bash
# Build libsodium for Android — three ABIs (arm64-v8a, armeabi-v7a, x86_64).
# Output: third_party/libsodium-android/<ABI>/{include,lib}/ (libsodium.a)
#
# Prereqs:
#   - ANDROID_NDK_HOME pointing at an installed NDK (r26+ recommended).
#     Install via: sdkmanager "ndk;26.3.11579264"
#   - third_party/libsodium/ source tree (run scripts/build-libsodium-wasm.sh
#     first, OR clone manually):
#       git clone --depth 1 --branch 1.0.21-RELEASE \
#                 https://github.com/jedisct1/libsodium.git \
#                 third_party/libsodium

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SODIUM_DIR="${REPO_ROOT}/third_party/libsodium"
OUT_BASE="${REPO_ROOT}/third_party/libsodium-android"

[[ -d "${SODIUM_DIR}" ]] || {
    echo "FAIL: libsodium source missing at ${SODIUM_DIR}" >&2
    echo "Clone it first: git clone --depth 1 --branch 1.0.21-RELEASE \\" >&2
    echo "                 https://github.com/jedisct1/libsodium.git ${SODIUM_DIR}" >&2
    exit 1
}
[[ -n "${ANDROID_NDK_HOME:-}" ]] || {
    echo "FAIL: ANDROID_NDK_HOME not set" >&2
    echo "Set it to your NDK install path, e.g.:" >&2
    echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.3.11579264" >&2
    exit 1
}

cd "${SODIUM_DIR}"
[[ -f configure ]] || ./autogen.sh -s

# libsodium ships per-ABI build helpers under dist-build/. Each writes its
# output into libsodium-android-<host>-<api>/ alongside the source. We copy
# the artefacts into ABI-keyed directories under third_party/libsodium-android/.

declare -A ABI_TO_SCRIPT=(
    ["arm64-v8a"]="android-armv8-a.sh"
    ["armeabi-v7a"]="android-armv7-a.sh"
    ["x86_64"]="android-x86_64.sh"
)
declare -A ABI_TO_OUTDIR=(
    ["arm64-v8a"]="libsodium-android-armv8-a+crypto"
    ["armeabi-v7a"]="libsodium-android-armv7-a"
    ["x86_64"]="libsodium-android-westmere"
)

for abi in "${!ABI_TO_SCRIPT[@]}"; do
    script="dist-build/${ABI_TO_SCRIPT[$abi]}"
    [[ -f "${script}" ]] || { echo "FAIL: ${script} missing in libsodium tree" >&2; exit 1; }
    echo "== building libsodium for ${abi}"
    ./"${script}"
    src="${SODIUM_DIR}/${ABI_TO_OUTDIR[$abi]}"
    dst="${OUT_BASE}/${abi}"
    mkdir -p "${dst}"
    cp -r "${src}"/* "${dst}/"
    echo "   -> ${dst}/lib/libsodium.a ($(wc -c <"${dst}/lib/libsodium.a") bytes)"
done

echo
echo "== installed libsodium-android prefixes:"
for abi in "${!ABI_TO_SCRIPT[@]}"; do
    ls -la "${OUT_BASE}/${abi}/lib/libsodium.a" 2>/dev/null || true
done
echo
echo "Now run: cd client-mobile-android && ./gradlew assembleDebug"
