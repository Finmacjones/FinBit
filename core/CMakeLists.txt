find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(BROTLIENC IMPORTED_TARGET libbrotlienc)
pkg_check_modules(BROTLIDEC IMPORTED_TARGET libbrotlidec)

# --- libsodium: try config package (vcpkg) first, then pkg-config (system) ----
find_package(unofficial-sodium CONFIG QUIET)
if(unofficial-sodium_FOUND)
    set(FB_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(FB_SODIUM_TARGET PkgConfig::SODIUM)
endif()

# --- protobuf: prefer modern CONFIG package; fall back to FindProtobuf module --
find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND)
    find_package(Protobuf REQUIRED)
endif()

find_package(fmt CONFIG QUIET)
if(NOT fmt_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FMT REQUIRED IMPORTED_TARGET fmt)
endif()

find_package(spdlog CONFIG QUIET)
if(NOT spdlog_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SPDLOG REQUIRED IMPORTED_TARGET spdlog)
endif()

# Asio is declared in vcpkg.json but is not yet used in code. Phase-0 build
# tolerates its absence; net/ work in Phase 0+ will require it.

set(FB_PROTO_FILES
    proto/envelope.proto
    proto/handshake.proto
    proto/ratchet.proto
    proto/sender_keys.proto
    proto/p2p.proto
    proto/dm_payload.proto
    proto/identity_log.proto
    proto/dht.proto
)

set(FB_PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${FB_PROTO_GEN_DIR})

set(FB_PROTO_SRCS)
set(FB_PROTO_HDRS)
foreach(proto ${FB_PROTO_FILES})
    get_filename_component(proto_name ${proto} NAME_WE)
    set(gen_src "${FB_PROTO_GEN_DIR}/${proto_name}.pb.cc")
    set(gen_hdr "${FB_PROTO_GEN_DIR}/${proto_name}.pb.h")
    add_custom_command(
        OUTPUT  ${gen_src} ${gen_hdr}
        COMMAND protobuf::protoc
        ARGS    --cpp_out=${FB_PROTO_GEN_DIR}
                -I${CMAKE_CURRENT_SOURCE_DIR}/proto
                ${CMAKE_CURRENT_SOURCE_DIR}/${proto}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${proto} protobuf::protoc
        COMMENT "protoc ${proto}"
        VERBATIM
    )
    list(APPEND FB_PROTO_SRCS ${gen_src})
    list(APPEND FB_PROTO_HDRS ${gen_hdr})
endforeach()

add_library(fb_core STATIC
    ${FB_PROTO_SRCS}
    src/crypto/identity.cpp
    src/crypto/aead.cpp
    src/crypto/hkdf.cpp
    src/crypto/ratchet.cpp
    src/crypto/sender_keys.cpp
    src/crypto/mls_facade.cpp
    src/net/frame_codec.cpp
    src/net/tcp.cpp
    src/net/io_loop.cpp
    src/net/websocket.cpp
    src/store/sqlite_store.cpp
    src/ratelimit/token_bucket.cpp
    src/media/peer_connection.cpp
    src/media/sframe.cpp
    src/mesh/mqtt_bridge.cpp
    src/mesh/serial_bridge.cpp
    src/mesh/compression.cpp
    src/p2p/host.cpp
    src/p2p/kademlia.cpp
    src/p2p/gossip.cpp
    src/p2p/provider_records.cpp
    src/p2p/dht_node.cpp
    src/p2p/bootstrap.cpp
    src/identity/username_log.cpp
    src/identity/username_gossip.cpp
    src/net/tls_client.cpp
)

target_include_directories(fb_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${FB_PROTO_GEN_DIR}>
)

if(TARGET fmt::fmt)
    set(FB_FMT_TARGET fmt::fmt)
else()
    set(FB_FMT_TARGET PkgConfig::FMT)
endif()
if(TARGET spdlog::spdlog)
    set(FB_SPDLOG_TARGET spdlog::spdlog)
else()
    set(FB_SPDLOG_TARGET PkgConfig::SPDLOG)
endif()

target_link_libraries(fb_core
    PUBLIC
        ${FB_SODIUM_TARGET}
        protobuf::libprotobuf
        ${FB_FMT_TARGET}
        ${FB_SPDLOG_TARGET}
        PkgConfig::SQLITE3
)

if(TARGET PkgConfig::BROTLIENC AND TARGET PkgConfig::BROTLIDEC)
    target_link_libraries(fb_core PUBLIC PkgConfig::BROTLIENC PkgConfig::BROTLIDEC)
    target_compile_definitions(fb_core PUBLIC FB_HAVE_BROTLI=1)
else()
    target_compile_definitions(fb_core PUBLIC FB_HAVE_BROTLI=0)
endif()

# --- Eclipse Paho MQTT C++ -------------------------------------------------
# Vendored under third_party/install (built once via scripts/build-paho.sh).
# Detected by looking for the install prefix; absent => mqtt bridge stays
# stub-throw and FB_HAVE_PAHO=0.
set(FB_PAHO_PREFIX "${CMAKE_SOURCE_DIR}/third_party/install" CACHE PATH "Paho install prefix")
if(EXISTS "${FB_PAHO_PREFIX}/lib/libpaho-mqttpp3.a")
    target_include_directories(fb_core PUBLIC "${FB_PAHO_PREFIX}/include")
    target_link_libraries(fb_core PUBLIC
        "${FB_PAHO_PREFIX}/lib/libpaho-mqttpp3.a"
        "${FB_PAHO_PREFIX}/lib/libpaho-mqtt3a.a"
    )
    target_compile_definitions(fb_core PUBLIC FB_HAVE_PAHO=1)
    message(STATUS "Paho MQTT C++ found at ${FB_PAHO_PREFIX}")
else()
    target_compile_definitions(fb_core PUBLIC FB_HAVE_PAHO=0)
    message(STATUS "Paho MQTT C++ not found — mesh::make_mqtt_bridge will throw")
endif()

# --- MLS (RFC 9420) via vendored mlspp -------------------------------------
# Gated on FB_FEATURE_MLS at the top-level CMakeLists. mls_facade.cpp
# checks FB_HAVE_MLS at compile time — without it the stub Throws-Not-
# Implemented body is used and SenderKeys remains the only channel cipher.
if(FB_FEATURE_MLS AND TARGET mlspp)
    # mlspp link is PRIVATE (mlspp types are hidden behind the
    # mls_facade.cpp PIMPL), but the FB_HAVE_MLS define is PUBLIC so
    # the test target — and any future consumer that wants to know
    # whether MLS is on — can branch on it.
    target_link_libraries(fb_core PRIVATE mlspp)
    target_compile_definitions(fb_core PUBLIC FB_HAVE_MLS=1)
    message(STATUS "fb_core: MLS (mlspp) ENABLED")
else()
    target_compile_definitions(fb_core PUBLIC FB_HAVE_MLS=0)
endif()

# --- OpenSSL for client-side TLS (TlsClient) ------------------------------
# Optional. Without it, fb::net::TlsClient throws "OpenSSL not compiled in"
# at every entry point, but everything links + builds. With it, FB_HAVE_OPENSSL
# is defined PUBLIC so consumers (fb-cli, chat_client) compile against
# the real implementation.
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(fb_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(fb_core PUBLIC FB_HAVE_OPENSSL=1)
    message(STATUS "fb_core: OpenSSL ${OPENSSL_VERSION} → TlsClient enabled")
else()
    target_compile_definitions(fb_core PUBLIC FB_HAVE_OPENSSL=0)
    message(STATUS "fb_core: OpenSSL NOT found → TlsClient throws on use")
endif()

target_compile_features(fb_core PUBLIC cxx_std_20)

add_library(fb::core ALIAS fb_core)

if(FB_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(FB_BUILD_BENCH)
    add_subdirectory(bench)
endif()
