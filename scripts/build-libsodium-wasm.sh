#!/usr/bin/env bash
# Build libsodium for WebAssembly via Emscripten.
#
# Prereq: emsdk activated (run `source ~/emsdk/emsdk_env.sh`).
#
# Output: third_party/libsodium/libsodium-js/{include,lib}/...
#         (libsodium.a is what scripts/build-wasm.sh links.)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SODIUM_DIR="${REPO_ROOT}/third_party/libsodium"

[[ -d "${SODIUM_DIR}" ]] || {
    echo "FAIL: libsodium source missing at ${SODIUM_DIR}" >&2
    echo "Run: git clone --depth 1 --branch 1.0.21-RELEASE \\" >&2
    echo "       https://github.com/jedisct1/libsodium.git \\" >&2
    echo "       ${SODIUM_DIR}" >&2
    exit 1
}
command -v emcc >/dev/null || {
    echo "FAIL: emcc not on PATH — source ~/emsdk/emsdk_env.sh first" >&2
    exit 1
}

cd "${SODIUM_DIR}"
[[ -f configure ]] || ./autogen.sh -s
./dist-build/emscripten.sh --standard

ls -la libsodium-js/lib/libsodium.a libsodium-js/include/sodium.h
echo "libsodium.a built for WASM. Now run scripts/build-wasm.sh."
