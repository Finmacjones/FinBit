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
# minimum: gstreamer-1.0 (core), gstreamer-sdp-1.0 (parsing SDP from the
# peer), gstreamer-webrtc-1.0 (webrtcbin element). The actual element
# implementations live in gst-plugins-base / good / bad / ugly — they're
# loaded at runtime so cmake doesn't need to find them, but the build
# scripts list them in the README so packagers know what to install.
find_package(PkgConfig REQUIRED)
pkg_check_modules(GSTREAMER REQUIRED IMPORTED_TARGET
    gstreamer-1.0
    gstreamer-app-1.0
    gstreamer-sdp-1.0
    gstreamer-webrtc-1.0
)

add_executable(fb_desktop
    src/main.cpp
    src/chat_client.cpp
    src/main_window.cpp
    src/avatar.cpp
    src/discord_theme.cpp
    src/message_delegate.cpp
    src/identity_vault.cpp
    src/login_dialog.cpp
    src/media_call.cpp
    src/bip39.cpp
    src/bip39_wordlist.cpp
)

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
        PkgConfig::GSTREAMER
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Concurrent
)
target_compile_features(fb_desktop PRIVATE cxx_std_20)
