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

if(MSVC)
    add_compile_options(/W4 /permissive-)
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
