# OpenSSL is optional — if found, the relay gains TLS support
# (--tls-port / --tls-cert / --tls-key). Without it, plain TCP/WS only.
find_package(OpenSSL QUIET)

# Embeddable relay: the epoll event loop + routing, factored into a library so
# it powers BOTH the standalone fb_server binary AND the desktop client's
# in-app relay (fb::server::run_relay on a background thread).
add_library(fb_relay STATIC
    src/relay_server.cpp
    src/relay.cpp
    src/directory.cpp
)
target_link_libraries(fb_relay PUBLIC fb::core)
target_include_directories(fb_relay PUBLIC src)
target_compile_features(fb_relay PUBLIC cxx_std_20)
if(OpenSSL_FOUND)
    target_link_libraries(fb_relay PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(fb_relay PUBLIC FB_HAVE_OPENSSL=1)
    message(STATUS "fb_relay: OpenSSL ${OPENSSL_VERSION} → TLS enabled")
else()
    message(STATUS "fb_relay: OpenSSL not found → TLS disabled")
endif()
add_library(fb::relay ALIAS fb_relay)

# Standalone relay daemon — thin CLI wrapper over the library.
add_executable(fb_server src/main.cpp)
target_link_libraries(fb_server PRIVATE fb_relay)
target_compile_features(fb_server PRIVATE cxx_std_20)
