#!/usr/bin/env bash
# Build the FinBit WASM module via Emscripten + the WASM-built libsodium.
#
# Prereqs:
#   - emsdk activated (run `source ~/emsdk/emsdk_env.sh`)
#   - libsodium WASM build present at third_party/libsodium/libsodium-js
#     (run `cd third_party/libsodium && ./dist-build/emscripten.sh --standard`)
#
# Output:
#   client-web/build/finbit.{js,wasm}

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/client-web/build"
SODIUM="${REPO_ROOT}/third_party/libsodium/libsodium-js"

[[ -f "${SODIUM}/lib/libsodium.a" ]] || {
    echo "FAIL: libsodium WASM build missing at ${SODIUM}" >&2
    echo "Run: cd ${REPO_ROOT}/third_party/libsodium && ./dist-build/emscripten.sh --standard" >&2
    exit 1
}
command -v emcc >/dev/null || {
    echo "FAIL: emcc not on PATH — source ~/emsdk/emsdk_env.sh first" >&2
    exit 1
}

mkdir -p "${OUT}"

# protobuf-lite for WASM (built once via `emmake make` against
# third_party/protobuf — see README "Optional dep build scripts").
PROTOBUF_BUILD="${REPO_ROOT}/third_party/protobuf/build-wasm"
PROTOBUF_SRC="${REPO_ROOT}/third_party/protobuf/src"
[[ -f "${PROTOBUF_BUILD}/libprotobuf-lite.a" ]] || {
    echo "FAIL: protobuf-lite WASM build missing at ${PROTOBUF_BUILD}" >&2
    echo "Run: scripts/build-protobuf-wasm.sh" >&2
    exit 1
}

# Use the protoc built from the SAME protobuf version as libprotobuf-lite
# (system protoc 4.x emits headers our vendored 3.21.12 runtime lacks).
PROTOC="${REPO_ROOT}/third_party/protobuf/build-native/protoc"
[[ -x "${PROTOC}" ]] || {
    echo "FAIL: vendored protoc missing at ${PROTOC}" >&2
    echo "Run: scripts/build-protobuf-wasm.sh (also builds the native protoc)" >&2
    exit 1
}

GEN_DIR="${OUT}/proto-gen"
mkdir -p "${GEN_DIR}"
"${PROTOC}" -I"${REPO_ROOT}/core/proto" --cpp_out="${GEN_DIR}" \
    "${REPO_ROOT}/core/proto/handshake.proto" \
    "${REPO_ROOT}/core/proto/sender_keys.proto" \
    "${REPO_ROOT}/core/proto/dm_payload.proto" \
    "${REPO_ROOT}/core/proto/envelope.proto" \
    "${REPO_ROOT}/core/proto/ratchet.proto"

# Common compile flags shared between the ES-module + CommonJS targets.
COMMON_ARGS=(
    -O2 -std=c++20
    -I"${REPO_ROOT}/core/include"
    -I"${SODIUM}/include"
    -I"${PROTOBUF_SRC}"
    -I"${GEN_DIR}"
    "${REPO_ROOT}/client-web/wasm-shim/finbit_wasm.cpp"
    "${REPO_ROOT}/core/src/crypto/identity.cpp"
    "${REPO_ROOT}/core/src/crypto/aead.cpp"
    "${REPO_ROOT}/core/src/crypto/hkdf.cpp"
    "${REPO_ROOT}/core/src/crypto/ratchet.cpp"
    "${REPO_ROOT}/core/src/crypto/sender_keys.cpp"
    "${GEN_DIR}/ratchet.pb.cc"
    "${GEN_DIR}/sender_keys.pb.cc"
    "${SODIUM}/lib/libsodium.a"
    "${PROTOBUF_BUILD}/libprotobuf-lite.a"
    -lembind
    -fexceptions
    -s MODULARIZE=1
    -s EXPORT_NAME=FinBitModule
    -s ALLOW_MEMORY_GROWTH=1
    -s ENVIRONMENT=node,web,worker
    -s DISABLE_EXCEPTION_CATCHING=0
    # Expose getExceptionMessage so JS can read C++ exception what() strings
    # (otherwise embind throws an opaque CppException { excPtr } and we can't
    # tell what failed). Used by FinBitConnection._tryWasm + node smoke tests.
    -s "EXPORTED_RUNTIME_METHODS=['getExceptionMessage']"
)

# 1. ES module (.mjs) — used by the browser UI via `import`.
emcc "${COMMON_ARGS[@]}" -s EXPORT_ES6=1 -o "${OUT}/finbit.mjs"

# 2. CommonJS (.js) — used by the Node.js smoke test via `require()`.
emcc "${COMMON_ARGS[@]}" -s EXPORT_ES6=0 -o "${OUT}/finbit.js"

echo "wrote:"
ls -la "${OUT}"/finbit.*
