// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/mesh/bridge.hpp"

#include <stdexcept>
#include <string>

// =============================================================================
// MQTT mesh bridge — Eclipse Paho C++ implementation.
//
// Built when the Paho install prefix exists at third_party/install (set by
// scripts/build-paho.sh). When absent, the factory throws so callers fail
// loudly. The wire side speaks plain MQTT 3.1.1; the application-side
// translates between MeshFrame and what the broker carries.
//
// MeshCore / Meshtastic public brokers traffic in protobuf-encoded
// ServiceEnvelope messages on topics like
//   `msh/2/c/<channel>/<region>`. For Phase-0 we don't yet decode that
// schema — the bridge just hands the raw payload bytes to the OnMeshFrame
// callback, and the application layer can decode further. Full Meshtastic
// protobuf decode lands when the schema is vendored.
// =============================================================================

#if FB_HAVE_PAHO

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>

#include <mqtt/async_client.h>

namespace fb::mesh {
namespace {

class PahoBridge final : public IBridge {
public:
    PahoBridge(std::string broker_url, std::string base_topic)
        : broker_url_(std::move(broker_url)), base_topic_(std::move(base_topic)) {}

    ~PahoBridge() override { stop(); }

    bool start() override {
        try {
            client_ = std::make_unique<mqtt::async_client>(broker_url_, /*client_id=*/"");
            client_->set_message_callback([this](mqtt::const_message_ptr m) {
                OnMeshFrame cb;
                {
                    std::lock_guard lk(cb_mu_);
                    cb = on_frame_;
                }
                if (!cb) return;
                MeshFrame mf;
                mf.origin = "mqtt";
                mf.topic = m->get_topic();
                const auto& payload = m->get_payload_str();
                mf.payload = std::vector<std::uint8_t>(payload.begin(), payload.end());
                cb(mf);
            });
            mqtt::connect_options opts;
            opts.set_clean_session(true);
            opts.set_keep_alive_interval(30);
            client_->connect(opts)->wait();
            // Subscribe to base_topic + wildcard so we see everything under
            // the configured prefix.
            const std::string sub = base_topic_.empty() ? std::string("#")
                                                        : base_topic_ + "/#";
            client_->subscribe(sub, /*qos=*/0)->wait();
            running_ = true;
            return true;
        } catch (const mqtt::exception& e) {
            last_error_ = std::string("paho: ") + e.what();
            return false;
        } catch (const std::exception& e) {
            last_error_ = std::string("std: ") + e.what();
            return false;
        }
    }

    void stop() override {
        if (!running_.exchange(false)) return;
        try {
            if (client_ && client_->is_connected()) {
                client_->disconnect()->wait();
            }
        } catch (...) {}
        client_.reset();
    }

    void set_on_frame(OnMeshFrame cb) override {
        std::lock_guard lk(cb_mu_);
        on_frame_ = std::move(cb);
    }

    bool send(const std::string& topic, std::span<const std::uint8_t> payload) override {
        if (!client_ || !client_->is_connected()) return false;
        try {
            const std::string full_topic = base_topic_.empty()
                                               ? topic
                                               : base_topic_ + "/" + topic;
            mqtt::message_ptr m = mqtt::make_message(
                full_topic,
                std::string(reinterpret_cast<const char*>(payload.data()), payload.size()));
            m->set_qos(0);
            client_->publish(m)->wait();
            return true;
        } catch (const std::exception& e) {
            last_error_ = std::string("publish: ") + e.what();
            return false;
        }
    }

    [[nodiscard]] const std::string& last_error() const noexcept { return last_error_; }

private:
    std::string broker_url_;
    std::string base_topic_;
    std::unique_ptr<mqtt::async_client> client_;
    std::atomic_bool running_{false};
    std::mutex cb_mu_;
    OnMeshFrame on_frame_;
    std::string last_error_;
};

}  // namespace

std::unique_ptr<IBridge> make_mqtt_bridge(const std::string& broker_url,
                                           const std::string& base_topic) {
    return std::make_unique<PahoBridge>(broker_url, base_topic);
}

}  // namespace fb::mesh

#else  // !FB_HAVE_PAHO

namespace fb::mesh {
std::unique_ptr<IBridge> make_mqtt_bridge(const std::string&, const std::string&) {
    throw std::runtime_error(
        "mesh::make_mqtt_bridge: built without Paho MQTT — see "
        "scripts/build-paho.sh");
}
}  // namespace fb::mesh

#endif
