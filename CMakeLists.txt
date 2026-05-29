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

# Binary hardening — applied to non-Debug, non-sanitizer builds. Compiles
# defenses against classic memory-safety exploits (smashed stack, ROP, GOT
# overwrite, uninitialized stack reads). Defaults ON because every flag here
# is free or near-free at runtime. See docs/censorship-resistance.md.
#
# Baseline already provided by modern toolchains (PIE, partial RELRO, NX
# stack, basic stack canary) — this block adds full RELRO, strong stack
# protector, _FORTIFY_SOURCE=3 + libstdc++ asserts, Intel CET shadow stack,
# and zero-init of stack autos. Skip in Debug (worsens debugging signal)
# and when sanitizers are on (they conflict with FORTIFY + canary).
option(FB_HARDEN "Apply binary-hardening flags (PIE/RELRO/CET/FORTIFY/canary)" ON)

if(FB_HARDEN AND NOT MSVC)
    set(_fb_harden_active OFF)
    set(_fb_harden_debug
        "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR
        "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug"
       AND NOT (FB_ENABLE_SANITIZERS AND "${CMAKE_BUILD_TYPE}" STREQUAL "Debug"))
        set(_fb_harden_active ON)
    endif()
    # We DO apply most hardening on RelWithDebInfo (the FinBit default) —
    # FORTIFY needs optimisation (-O>=1), but everything else is fine.

    if(_fb_harden_active)
        # ---- Compiler ----
        # Strong stack protector — covers every function with a stack
        # buffer, address-of-local, alloca, or local array. Cost: ~1%
        # at function epilogue.
        add_compile_options(-fstack-protector-strong)

        # _FORTIFY_SOURCE=3 — checked memcpy/strcpy/snprintf/etc. via
        # __builtin_object_size; catches more overflows than =2 by using
        # whole-program object-size knowledge. Available on glibc 2.34+
        # (Ubuntu 22.04 / Debian 12 / Arch). Needs -O >= 1.
        add_compile_options(
            "$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-U_FORTIFY_SOURCE>"
            "$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-D_FORTIFY_SOURCE=3>"
        )

        # libstdc++ assertions — bounds-checks on operator[], front(),
        # back(), iterator misuse. Catches a meaningful class of UB at
        # runtime with small overhead.
        add_compile_definitions(_GLIBCXX_ASSERTIONS)

        # Zero-init stack autos — eliminates entire classes of
        # use-of-uninitialized-stack bugs at ~0.5% runtime cost. Needs
        # gcc 12+ / clang 16+; gracefully ignored on older toolchains
        # via CheckCXXCompilerFlag-style guard below.
        include(CheckCXXCompilerFlag)
        check_cxx_compiler_flag(-ftrivial-auto-var-init=zero
                                FB_HAS_TRIVIAL_AUTO_VAR_INIT)
        if(FB_HAS_TRIVIAL_AUTO_VAR_INIT)
            add_compile_options(-ftrivial-auto-var-init=zero)
        endif()

        # Intel CET (Indirect Branch Tracking + Shadow Stack) on x86_64.
        # Hardware-enforced control-flow integrity; needs CPU support
        # (Tigerlake+ / Zen 4+) and a glibc compiled with CET. Compiles
        # to NOP if the CPU lacks it.
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
            check_cxx_compiler_flag(-fcf-protection=full FB_HAS_CET)
            if(FB_HAS_CET)
                add_compile_options(-fcf-protection=full)
            endif()
        endif()

        # ---- Linker ----
        # Full RELRO + immediate bind: marks GOT read-only after dynamic
        # linker resolves all symbols at startup, defeating GOT-overwrite
        # ROP gadgets. Pair with NX stack (already on by default).
        if(NOT APPLE)
            add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()

        message(STATUS "FB_HARDEN: full RELRO + stack-protector-strong + "
                       "_FORTIFY_SOURCE=3 + _GLIBCXX_ASSERTIONS"
                       "$<$<BOOL:${FB_HAS_TRIVIAL_AUTO_VAR_INIT}>: + trivial-auto-var-init=zero>"
                       "$<$<BOOL:${FB_HAS_CET}>: + Intel CET>")
    else()
        message(STATUS "FB_HARDEN: skipped (Debug or sanitizers active)")
    endif()
    unset(_fb_harden_active)
    unset(_fb_harden_debug)
endif()

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
