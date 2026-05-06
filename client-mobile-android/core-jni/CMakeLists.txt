cmake_minimum_required(VERSION 3.24)
project(fb_core_jni LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# --- libsodium for Android ABI ----------------------------------------------
# scripts/build-libsodium-android.sh produces:
#   third_party/libsodium-android/<ABI>/lib/libsodium.a
#   third_party/libsodium-android/<ABI>/include/sodium.h
# Gradle's externalNativeBuild passes ANDROID_ABI; we use it to pick the
# right per-ABI prefix.
if(NOT DEFINED FB_ANDROID_LIBSODIUM_PREFIX)
    set(FB_ANDROID_LIBSODIUM_PREFIX
        "${REPO_ROOT}/third_party/libsodium-android/${ANDROID_ABI}")
endif()

if(NOT EXISTS "${FB_ANDROID_LIBSODIUM_PREFIX}/lib/libsodium.a")
    message(FATAL_ERROR
        "libsodium-android not built for ABI ${ANDROID_ABI}.\n"
        "Run: scripts/build-libsodium-android.sh\n"
        "Looked for: ${FB_ANDROID_LIBSODIUM_PREFIX}/lib/libsodium.a")
endif()

add_library(libsodium_static STATIC IMPORTED)
set_target_properties(libsodium_static PROPERTIES
    IMPORTED_LOCATION "${FB_ANDROID_LIBSODIUM_PREFIX}/lib/libsodium.a"
    INTERFACE_INCLUDE_DIRECTORIES "${FB_ANDROID_LIBSODIUM_PREFIX}/include")

# --- fb::core subset (crypto only — same files Emscripten builds) ----------
add_library(fb_core_jni SHARED
    "${REPO_ROOT}/core/src/crypto/identity.cpp"
    "${REPO_ROOT}/core/src/crypto/aead.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/jni_bridge.cpp"
)

target_include_directories(fb_core_jni PRIVATE
    "${REPO_ROOT}/core/include"
)

target_link_libraries(fb_core_jni PRIVATE
    libsodium_static
    log
    android
)

target_compile_options(fb_core_jni PRIVATE -Wall -Wextra -Wpedantic)
