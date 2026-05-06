find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

add_executable(fb_core_tests
    crypto/kat_aead_test.cpp
    crypto/identity_test.cpp
    crypto/hkdf_test.cpp
    crypto/ratchet_test.cpp
    crypto/sender_keys_test.cpp
    net/frame_codec_test.cpp
    net/websocket_test.cpp
    store/sqlite_store_test.cpp
    ratelimit/token_bucket_test.cpp
    media/sframe_test.cpp
    mesh/compression_test.cpp
    mesh/serial_bridge_test.cpp
    mesh/mqtt_bridge_test.cpp
    p2p/kademlia_test.cpp
    p2p/gossip_test.cpp
)

target_link_libraries(fb_core_tests
    PRIVATE
        fb::core
        GTest::gtest
        GTest::gtest_main
)

gtest_discover_tests(fb_core_tests)
