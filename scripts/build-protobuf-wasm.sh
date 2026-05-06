#!/usr/bin/env bash
# Build protobuf-lite for WASM via Emscripten.
#
# Required for scripts/build-wasm.sh once the WASM client links any
# protobuf-generated source (currently ratchet.pb.cc).
#
# Prereqs: emsdk activated (run `source ~/emsdk/emsdk_env.sh`).

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PB_DIR="${REPO_ROOT}/third_party/protobuf"

[[ -d "${PB_DIR}" ]] || {
    echo "Cloning protobuf v3.21.12 into ${PB_DIR}…"
    git clone --depth 1 --branch v3.21.12 \
        https://github.com/protocolbuffers/protobuf.git "${PB_DIR}"
    (cd "${PB_DIR}" && git submodule update --init --recursive --depth 1)
}

command -v emcc >/dev/null || {
    echo "FAIL: emcc not on PATH — source ~/emsdk/emsdk_env.sh first" >&2
    exit 1
}

cd "${PB_DIR}"
emcmake cmake -B build-wasm -S cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_PROTOC_BINARIES=OFF \
    -Dprotobuf_BUILD_LIBPROTOC=OFF \
    -Dprotobuf_BUILD_SHARED_LIBS=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
emmake make -C build-wasm libprotobuf-lite -j

ls -la build-wasm/libprotobuf-lite.a
echo "OK: protobuf-lite for WASM ready. Now run scripts/build-wasm.sh."
