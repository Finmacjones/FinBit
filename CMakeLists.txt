cmake_minimum_required(VERSION 3.24)

project(FinBit
    VERSION 0.0.1
    DESCRIPTION "FinBit — E2E encrypted, mesh-bridged, eventually decentralized chat"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

option(FB_BUILD_TESTS "Build test suites" ON)
option(FB_BUILD_BENCH "Build microbenchmarks" OFF)
option(FB_BUILD_SERVER "Build the relay server" ON)
option(FB_BUILD_DESKTOP_CLIENT "Build the Qt6 desktop client" OFF)
option(FB_BUILD_TOOLS "Build CLI / dev tooling" ON)
option(FB_ENABLE_SANITIZERS "Enable ASan + UBSan in Debug" ON)
# MLS (RFC 9420) channel crypto — vendored mlspp under third_party/mlspp.
# OFF by default until the integration stabilises; SenderKeys remains the
# default channel cipher in the meantime.
option(FB_FEATURE_MLS "Enable MLS group crypto via vendored mlspp" OFF)

# Reproducible-build mode. When ON, applies compiler/linker flags that strip
# build-machine state from the output (absolute paths in debug info, random
# section names, build IDs). Combined with SOURCE_DATE_EPOCH and a workflow
# that builds twice on the same revision and compares hashes, this lets any
# third party verify a published binary corresponds bit-for-bit to the git
# tag — defeating supply-chain attacks where a compromised builder silently
# inserts a backdoor. See .github/workflows/reproducible.yml and
# docs/censorship-resistance.md (Tier 8). OFF by default (debug ergonomics
# matter more for normal dev; CI flips this on for release tags).
option(FB_REPRODUCIBLE_BUILD "Apply reproducible-build flags" OFF)

if(FB_REPRODUCIBLE_BUILD)
    # Strip absolute source paths from debug info + __FILE__ macros so a
    # binary built under /home/alice/finbit and one built under
    # /tmp/build-42/finbit are byte-identical.
    add_compile_options(
        -ffile-prefix-map=${CMAKE_SOURCE_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.
        -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=.
    )
    # Deterministic random section names in object files (gcc inserts a
    # randomly-seeded hash into anonymous-namespace symbols by default).
    add_compile_options(-frandom-seed=fb-deterministic)
    # Linker: replace the random build-id with a deterministic SHA1 over the
    # final binary's hash sections.
    if(NOT APPLE AND NOT MSVC)
        add_link_options(-Wl,--build-id=sha1)
    endif()
    # Honour SOURCE_DATE_EPOCH end-to-end (CMake sets timestamps in the
    # install tree from it when set). Surfacing here so a configure-time
    # log shows the operator what value will be baked in.
    if(DEFINED ENV{SOURCE_DATE_EPOCH})
        message(STATUS "Reproducible build: SOURCE_DATE_EPOCH=$ENV{SOURCE_DATE_EPOCH}")
    else()
        message(WARNING "FB_REPRODUCIBLE_BUILD ON but SOURCE_DATE_EPOCH unset — "
                        "embedded timestamps will still leak. Set it to the "
                        "commit's author date for full reproducibility.")
    endif()
endif()

if(MSVC)
    add_compile_options(/W4 /permissive-)
    # windows.h #defines `min` and `max` as function-like macros which
    # collide with std::min / std::numeric_limits<T>::max(). NOMINMAX
    # disables them. _CRT_SECURE_NO_WARNINGS silences C4996 on
    # std::getenv etc. that the CRT marks "unsafe" but we use safely.
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    if(FB_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

if(FB_BUILD_TESTS)
    enable_testing()
endif()

if(FB_FEATURE_MLS)
    # mlspp options: skip its own tests and post-quantum (liboqs) since we
    # don't ship those. EXCLUDE_FROM_ALL means mlspp targets only build
    # when something actually links against them.
    set(TESTING OFF CACHE BOOL "" FORCE)
    set(DISABLE_PQ ON CACHE BOOL "" FORCE)
    set(MLS_NAMESPACE_SUFFIX "" CACHE STRING "" FORCE)
    # mlspp uses -Werror; combined with our top-level -Wconversion that
    # makes its source fail to compile. Strip our diagnostic flags off
    # the vendored subdirectory and let mlspp use its own.
    add_subdirectory(third_party/mlspp EXCLUDE_FROM_ALL)
    foreach(target tls_syntax bytes hpke mls_ds mls_vectors mlspp)
        if(TARGET ${target})
            if(MSVC)
                # mlspp's own CMakeLists may add /WX or treat-warnings-as-
                # errors style flags on the MSVC arm; silence them here
                # without trying to translate the GCC -Wno-* dialect.
                target_compile_options(${target} PRIVATE /W3 /WX-)
            else()
                target_compile_options(${target} PRIVATE
                    -Wno-conversion -Wno-shadow -Wno-pedantic -Wno-error)
            endif()
        endif()
    endforeach()
endif()

add_subdirectory(core)

if(FB_BUILD_SERVER)
    add_subdirectory(server)
endif()

if(FB_BUILD_DESKTOP_CLIENT)
    add_subdirectory(client-desktop)
endif()

if(FB_BUILD_TOOLS)
    add_subdirectory(tools)
endif()
