// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// MeshCore / Meshtastic bridge — Phase 4 scaffolding.
//
// Two ingestion paths, both producing a normalized MeshFrame that the channel
// layer can ferry into a designated bridge channel:
//   - MQTT subscriber: consumes a public broker (e.g. mqtt.meshtastic.org)
//     and parses MeshCore/Meshtastic ServiceEnvelope frames.
//   - Serial companion node: opens /dev/ttyUSB0 (or COM3) and speaks the
//     device's protobuf-over-serial protocol.
//
// Outbound: a Discord-clone message destined for a mesh-bridged channel is
// passed through compress() (brotli + static dictionary) then fragmented to
// fit MeshCore's ~200-byte payload limit.
//
// PHASE 0 STATUS: interface real; impls stubbed. MQTT needs Eclipse Paho C++
// (`mesh` feature in vcpkg.json). Serial uses POSIX termios (no extra dep)
// and is the easier of the two to implement first.
// =============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace fb::mesh {

struct MeshFrame {
    std::string  origin;      // node short name or hex id
    std::string  topic;       // "primary" / numeric channel
    std::int32_t snr_db = 0;
    std::int32_t hop_limit = 0;
    std::vector<std::uint8_t> payload;  // decoded payload (text or binary)
};

class IBridge {
public:
    using OnMeshFrame = std::function<void(const MeshFrame&)>;

    virtual ~IBridge() = default;

    virtual bool start() = 0;
    virtual void stop() = 0;

    virtual void set_on_frame(OnMeshFrame cb) = 0;

    // Send a payload over the mesh. The bridge owns chunking + framing.
    [[nodiscard]] virtual bool send(const std::string& topic,
                                    std::span<const std::uint8_t> payload) = 0;
};

[[nodiscard]] std::unique_ptr<IBridge> make_mqtt_bridge(const std::string& broker_url,
                                                       const std::string& base_topic);

[[nodiscard]] std::unique_ptr<IBridge> make_serial_bridge(const std::string& device_path,
                                                         std::uint32_t baud);

// Compression helpers (brotli + per-protocol static dictionary). Used to
// shoehorn ChatMessage protobufs into a single 200-byte LoRa frame whenever
// possible. Returns the compressed bytes.
[[nodiscard]] std::vector<std::uint8_t> compress_for_mesh(std::span<const std::uint8_t> in);
[[nodiscard]] std::vector<std::uint8_t> decompress_from_mesh(std::span<const std::uint8_t> in);

}  // namespace fb::mesh
