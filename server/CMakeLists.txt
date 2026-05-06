# OpenSSL is optional — if found, fb_server gains TLS support
# (--tls-port / --tls-cert / --tls-key flags). Without it, the server
# still builds and listens on plain TCP/WS only.
find_package(OpenSSL QUIET)

add_executable(fb_server
    src/main.cpp
    src/relay.cpp
    src/directory.cpp
)

target_link_libraries(fb_server PRIVATE fb::core)
target_include_directories(fb_server PRIVATE src)
target_compile_features(fb_server PRIVATE cxx_std_20)

if(OpenSSL_FOUND)
    target_link_libraries(fb_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(fb_server PRIVATE FB_HAVE_OPENSSL=1)
    message(STATUS "fb_server: OpenSSL ${OPENSSL_VERSION} → --tls-* flags enabled")
else()
    message(STATUS "fb_server: OpenSSL not found → --tls-* flags disabled")
endif()
