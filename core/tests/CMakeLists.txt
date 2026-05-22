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
    net/ws_client_test.cpp
    net/doh_resolver_test.cpp
    net/tls_fingerprint_test.cpp
    net/ech_test.cpp
    store/sqlite_store_test.cpp
    store/attachment_frame_test.cpp
    identity/username_log_test.cpp
    identity/username_gossip_test.cpp
    integration/mls_persistence_integration_test.cpp
    ratelimit/token_bucket_test.cpp
    media/sframe_test.cpp
    media/active_speaker_test.cpp
    media/forwarder_test.cpp
    media/room_keys_test.cpp
    media/track_bindings_test.cpp
    mesh/compression_test.cpp
    mesh/mqtt_bridge_test.cpp
    p2p/kademlia_test.cpp
    p2p/gossip_test.cpp
    p2p/provider_records_test.cpp
    p2p/dht_node_test.cpp
    p2p/bootstrap_test.cpp
    p2p/peer_net_test.cpp
    p2p/offline_relay_test.cpp
    p2p/channel_gossip_test.cpp
    p2p/room_beacon_leak_test.cpp
)

# Serial-bridge test uses posix_openpt + ptmx PTY plumbing — POSIX
# only. The bridge IMPLEMENTATION compiles on Windows (Win32
# CreateFile + DCB backend), but exercising it would need a CI
# runner with a real COM port or a virtual loopback driver. The
# Linux test stands in for the cross-platform contract.
if(NOT WIN32)
    target_sources(fb_core_tests PRIVATE mesh/serial_bridge_test.cpp)
endif()

target_link_libraries(fb_core_tests
    PRIVATE
        fb::core
        GTest::gtest
        GTest::gtest_main
)

# The MQTT-bridge test spawns the loopback broker from tools/mesh-loopback.
# Bake the repo's path in at build time (overridable at runtime via
# FB_MQTT_BROKER_PY) so the test is portable — no hardcoded absolute path.
target_compile_definitions(fb_core_tests PRIVATE
    FB_MESH_LOOPBACK_DIR="${CMAKE_SOURCE_DIR}/tools/mesh-loopback")

gtest_discover_tests(fb_core_tests)
