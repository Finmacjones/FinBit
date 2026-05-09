find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

add_executable(fb_core_tests
    crypto/kat_aead_test.cpp
    crypto/identity_test.cpp
    crypto/identity_cert_test.cpp
    crypto/hkdf_test.cpp
    crypto/ratchet_test.cpp
    crypto/sender_keys_test.cpp
    crypto/mls_facade_test.cpp
    net/frame_codec_test.cpp
    net/websocket_test.cpp
    store/sqlite_store_test.cpp
    identity/username_log_test.cpp
    identity/username_gossip_test.cpp
    integration/mls_persistence_integration_test.cpp
    ratelimit/token_bucket_test.cpp
    media/sframe_test.cpp
    mesh/compression_test.cpp
    mesh/serial_bridge_test.cpp
    mesh/mqtt_bridge_test.cpp
    p2p/kademlia_test.cpp
    p2p/gossip_test.cpp
    p2p/provider_records_test.cpp
    p2p/dht_node_test.cpp
    p2p/bootstrap_test.cpp
    p2p/peer_net_test.cpp
    p2p/offline_relay_test.cpp
    p2p/channel_gossip_test.cpp
)

target_link_libraries(fb_core_tests
    PRIVATE
        fb::core
        GTest::gtest
        GTest::gtest_main
)

gtest_discover_tests(fb_core_tests)
