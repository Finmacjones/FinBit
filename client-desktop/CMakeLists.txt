find_package(Qt6 COMPONENTS Core Gui Widgets Concurrent)
if(NOT Qt6_FOUND)
    message(STATUS "client-desktop: Qt 6 (Core/Gui/Widgets/Concurrent) not found — skipping fb_desktop build")
    message(STATUS "  Install:  apt install qt6-base-dev qt6-tools-dev      (Ubuntu/Debian)")
    message(STATUS "            pacman -S qt6-base qt6-tools                (Arch)")
    return()
endif()
message(STATUS "client-desktop: Qt ${Qt6_VERSION} found at ${Qt6_DIR}")

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# GStreamer is the media backend for 1:1 voice/video. We pull the bare
# minimum: gstreamer-1.0 (core), gstreamer-sdp-1.0 (parsing SDP from
# the peer), gstreamer-webrtc-1.0 (webrtcbin element). The actual
# element implementations live in gst-plugins-base / good / bad /
# ugly — they're loaded at runtime.
#
# OPTIONAL on Windows. Chocolatey's gstreamer-devel ships pkgconfig
# files at C:\gstreamer\1.0\msvc_x86_64\lib\pkgconfig\ but the
# Windows MSI install sometimes lands without the .pc files (depends
# on installer version). When pkg-config can't find GStreamer we
# build a chat-only desktop client (no voice/video buttons) — better
# than failing the entire Windows desktop build.
find_package(PkgConfig)
set(FB_HAVE_GSTREAMER 0)
if(PkgConfig_FOUND)
    pkg_check_modules(GSTREAMER IMPORTED_TARGET
        gstreamer-1.0
        gstreamer-app-1.0
        gstreamer-sdp-1.0
        gstreamer-webrtc-1.0
    )
    if(GSTREAMER_FOUND)
        set(FB_HAVE_GSTREAMER 1)
        message(STATUS "client-desktop: GStreamer ${GSTREAMER_VERSION} — voice/video enabled")
    else()
        message(STATUS "client-desktop: GStreamer not found — building chat-only (no voice/video)")
    endif()
else()
    message(STATUS "client-desktop: pkg-config not found — building chat-only (no voice/video)")
endif()

add_executable(fb_desktop
    src/main.cpp
    src/chat_client.cpp
    src/main_window.cpp
    src/avatar.cpp
    src/discord_theme.cpp
    src/message_delegate.cpp
    src/identity_vault.cpp
    src/login_dialog.cpp
    src/verify_identity_dialog.cpp
    src/shamir_setup_wizard.cpp
    src/media_call.cpp
    src/room_forwarder.cpp
    src/crt_overlay.cpp
    src/bip39.cpp
    src/bip39_wordlist.cpp
)
target_compile_definitions(fb_desktop PRIVATE FB_HAVE_GSTREAMER=${FB_HAVE_GSTREAMER})

# libsodium is already a dependency of fb_core (transitively for the
# Identity / AEAD primitives) — but identity_vault.cpp pulls it in directly
# for crypto_pwhash (Argon2id) and the xchacha20 IETF AEAD wrappers, so
# resolve the import explicitly here too.
find_package(unofficial-sodium CONFIG QUIET)
if(unofficial-sodium_FOUND)
    set(_sodium_target unofficial-sodium::sodium)
else()
    find_library(SODIUM_LIBRARY sodium REQUIRED)
    set(_sodium_target ${SODIUM_LIBRARY})
endif()

target_link_libraries(fb_desktop
    PRIVATE
        fb::core
        ${_sodium_target}
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Concurrent
)
if(FB_HAVE_GSTREAMER)
    target_link_libraries(fb_desktop PRIVATE PkgConfig::GSTREAMER)
endif()

# In-app relay: if the relay library was built (FB_BUILD_SERVER on, on a
# platform where it compiles), link it so the desktop can host the network
# alongside the client (Settings ▸ host a relay). Otherwise the desktop is a
# pure client and the feature compiles out.
if(TARGET fb_relay)
    target_link_libraries(fb_desktop PRIVATE fb_relay)
    target_compile_definitions(fb_desktop PRIVATE FB_HAVE_EMBEDDED_RELAY=1)
    message(STATUS "fb_desktop: in-app relay enabled (links fb_relay)")
else()
    target_compile_definitions(fb_desktop PRIVATE FB_HAVE_EMBEDDED_RELAY=0)
    message(STATUS "fb_desktop: in-app relay unavailable (fb_relay not built)")
endif()

target_compile_features(fb_desktop PRIVATE cxx_std_20)
