#!/usr/bin/env bash
# Build Eclipse Paho MQTT C and C++ static libraries into
# third_party/install. Required for FB_HAVE_PAHO=1 (real MQTT mesh
# bridge); without it, mesh::make_mqtt_bridge throws.
#
# CMake 4 needs CMAKE_POLICY_VERSION_MINIMUM=3.5 to consume Paho 1.3.x's
# pre-3.5 policies. gcc 15 needs -std=gnu11 -Wno-error to handle Paho's
# legacy `typedef int bool` etc.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="${REPO_ROOT}/third_party"
PREFIX="${TP}/install"

clone_if_missing() {
    local dir="$1" url="$2" branch="$3"
    [[ -d "${dir}" ]] && return
    git clone --depth 1 --branch "${branch}" "${url}" "${dir}"
}

clone_if_missing "${TP}/paho.mqtt.c"   "https://github.com/eclipse/paho.mqtt.c.git"   v1.3.13
clone_if_missing "${TP}/paho.mqtt.cpp" "https://github.com/eclipse/paho.mqtt.cpp.git" v1.4.1

mkdir -p "${PREFIX}"

echo "== building paho.mqtt.c"
rm -rf "${TP}/paho.mqtt.c/build"
cmake -S "${TP}/paho.mqtt.c" -B "${TP}/paho.mqtt.c/build" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_C_STANDARD=11 \
    -DCMAKE_C_FLAGS="-std=gnu11 -Wno-error" \
    -DPAHO_WITH_SSL=FALSE \
    -DPAHO_BUILD_STATIC=TRUE \
    -DPAHO_BUILD_SHARED=FALSE \
    -DPAHO_BUILD_DOCUMENTATION=FALSE \
    -DPAHO_BUILD_SAMPLES=FALSE
cmake --build "${TP}/paho.mqtt.c/build" -j
cmake --install "${TP}/paho.mqtt.c/build"

echo "== building paho.mqtt.cpp"
rm -rf "${TP}/paho.mqtt.cpp/build"
cmake -S "${TP}/paho.mqtt.cpp" -B "${TP}/paho.mqtt.cpp/build" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    -DPAHO_WITH_SSL=FALSE \
    -DPAHO_BUILD_STATIC=TRUE \
    -DPAHO_BUILD_SHARED=FALSE \
    -DPAHO_BUILD_DOCUMENTATION=FALSE \
    -DPAHO_BUILD_SAMPLES=FALSE
cmake --build "${TP}/paho.mqtt.cpp/build" -j
cmake --install "${TP}/paho.mqtt.cpp/build"

echo "== installed:"
ls -la "${PREFIX}/lib"/libpaho-mqttpp3.a "${PREFIX}/lib"/libpaho-mqtt3a.a
echo "== reconfigure FinBit (cmake will pick up FB_HAVE_PAHO=1):"
echo "   cmake -S ${REPO_ROOT} -B ${REPO_ROOT}/build/system"
