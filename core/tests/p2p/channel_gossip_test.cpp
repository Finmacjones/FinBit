// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// channel_gossip gtests.
//
// Coverage:
//   - channel_topic_name produces the deterministic
//     "fb-chan:<hex(channel_id)>" string + rejects wrong-size input
//   - 3-node chain (A↔B↔C) all subscribed to the same channel topic;
//     A publishes a serialized Envelope, B + C receive it byte-for-byte.
//     Validates that channel envelope fan-out works without ANY central
//     server in the loop — uses fb::p2p::P2PNode directly with the
//     channel topic naming convention from channel_gossip.hpp.
// =============================================================================

#include "fb/p2p/channel_gossip.hpp"
#include "fb/p2p/gossip.hpp"

#include "envelope.pb.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

std::uint16_t free_port() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    socklen_t sl = sizeof(sa);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &sl);
    ::close(fd);
    return ntohs(sa.sin_port);
}

std::vector<std::uint8_t> rand_pubkey() {
    std::vector<std::uint8_t> out(32);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(::rand());
    }
    return out;
}

}  // namespace

TEST(ChannelGossip, TopicNameIsDeterministicAndHexEncoded) {
    std::vector<std::uint8_t> id(32, 0);
    EXPECT_EQ(fb::p2p::channel_topic_name(
        std::span<const std::uint8_t>(id.data(), id.size())),
        "fb-chan:" + std::string(64, '0'));

    std::vector<std::uint8_t> ff(32, 0xff);
    EXPECT_EQ(fb::p2p::channel_topic_name(
        std::span<const std::uint8_t>(ff.data(), ff.size())),
        "fb-chan:" + std::string(64, 'f'));

    std::vector<std::uint8_t> mix(32);
    for (std::size_t i = 0; i < mix.size(); ++i) mix[i] = static_cast<std::uint8_t>(i);
    auto t = fb::p2p::channel_topic_name(
        std::span<const std::uint8_t>(mix.data(), mix.size()));
    EXPECT_EQ(t.substr(0, 8), "fb-chan:");
    EXPECT_EQ(t.size(), 8u + 64u);
    // First two hex chars = byte 0 = 0x00; last two = byte 31 = 0x1f.
    EXPECT_EQ(t.substr(8, 2),  "00");
    EXPECT_EQ(t.substr(70, 2), "1f");
}

TEST(RoomGossip, TopicNameDeterministicAndDistinctFromChannel) {
    std::vector<std::uint8_t> id(32, 0xaa);
    auto chan = fb::p2p::channel_topic_name(
        std::span<const std::uint8_t>(id.data(), id.size()));
    auto room = fb::p2p::room_topic_name(
        std::span<const std::uint8_t>(id.data(), id.size()));
    EXPECT_EQ(chan, "fb-chan:" + std::string(64, 'a'));
    EXPECT_EQ(room, "fb-room:" + std::string(64, 'a'));
    EXPECT_NE(chan, room);   // distinct prefixes prevent crosstalk
}

// Server-free voice-room presence: A and B both subscribe to the
// same `fb-room:<hex>` topic and publish a Frame{room_roster} beacon
// listing themselves as the only participant. After both beacons
// have crossed the wire, each side's union-of-beacons matches the
// roster the central server would have broadcast — i.e. each side
// can see the other in the room without the server in the loop.
//
// Production wiring: ChatClient.kRoomJoin subscribes to the topic +
// publishes the beacon, ChatClient's overlay-inbox drain merges
// arriving beacons into Impl::room_gossip_known, and
// apply_room_roster() feeds the union into the same mesh-dial logic
// the server-side Frame.room_roster handler uses.
TEST(RoomGossip, TwoNodeBeaconUnionMatchesServerRoster) {
    const auto pa = free_port(), pb = free_port();
    auto pub_a = rand_pubkey();
    auto pub_b = rand_pubkey();
    fb::p2p::P2PNode A("127.0.0.1", pa, pub_a);
    fb::p2p::P2PNode B("127.0.0.1", pb, pub_b);
    A.start(); B.start();
    A.dial("127.0.0.1", pb);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::array<std::uint8_t, 32> room_id{};
    for (std::size_t i = 0; i < room_id.size(); ++i) room_id[i] = 0x37;
    const std::string topic = fb::p2p::room_topic_name(
        std::span<const std::uint8_t>(room_id.data(), room_id.size()));

    // Each node merges incoming beacons into its own peer-pubkey set,
    // mirroring Impl::room_gossip_known on the desktop client. Self
    // is added unconditionally below to mirror the synth-roster step.
    std::mutex mu;
    std::condition_variable cv;
    std::map<std::string, std::set<std::vector<std::uint8_t>>> known;

    auto on_msg = [&](const std::string& which) {
        return [&, which](const std::string& t,
                          std::span<const std::uint8_t> payload,
                          const fb::p2p::PeerInfo&) {
            EXPECT_EQ(t, topic);
            fb::proto::Frame f;
            ASSERT_TRUE(f.ParseFromArray(payload.data(),
                                          static_cast<int>(payload.size())));
            ASSERT_EQ(f.body_case(), fb::proto::Frame::kRoomRoster);
            std::lock_guard lk(mu);
            for (const auto& p : f.room_roster().participants()) {
                if (p.identity_pubkey().size() == 32) {
                    known[which].insert(std::vector<std::uint8_t>(
                        p.identity_pubkey().begin(),
                        p.identity_pubkey().end()));
                }
            }
            cv.notify_all();
        };
    };
    A.set_on_topic_message(on_msg("A"));
    B.set_on_topic_message(on_msg("B"));
    A.subscribe(topic);
    B.subscribe(topic);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    auto publish_beacon = [&](fb::p2p::P2PNode& n,
                              const std::vector<std::uint8_t>& self) {
        fb::proto::Frame beacon;
        auto* m = beacon.mutable_room_roster();
        m->set_room_id(std::string(room_id.begin(), room_id.end()));
        auto* mem = m->add_participants();
        mem->set_identity_pubkey(std::string(self.begin(), self.end()));
        mem->set_has_audio(true);
        mem->set_has_video(false);
        std::vector<std::uint8_t> bw(beacon.ByteSizeLong());
        ASSERT_TRUE(beacon.SerializeToArray(bw.data(),
                                              static_cast<int>(bw.size())));
        n.publish(topic, std::span<const std::uint8_t>(bw.data(), bw.size()));
    };
    publish_beacon(A, pub_a);
    publish_beacon(B, pub_b);

    // After both beacons settle, each side's union (gossip-known +
    // self) must equal {pub_a, pub_b} — same roster the server
    // would have built from RoomJoin × 2.
    {
        std::unique_lock lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2), [&] {
            return !known["A"].empty() && !known["B"].empty();
        })) << "no beacons crossed the wire";
    }
    auto union_with_self = [&](const std::string& who,
                               const std::vector<std::uint8_t>& self) {
        std::lock_guard lk(mu);
        auto u = known[who];
        u.insert(self);
        return u;
    };
    const std::set<std::vector<std::uint8_t>> expected{pub_a, pub_b};
    EXPECT_EQ(union_with_self("A", pub_a), expected);
    EXPECT_EQ(union_with_self("B", pub_b), expected);

    A.stop(); B.stop();
}

// Late-joiner discovery: A joins a room and publishes once, B joins
// LATER. With a one-shot beacon B never sees A. With periodic
// republish (kRoomPresenceRepublishMs in the desktop client), B's
// subscriber callback eventually receives the next beacon cycle and
// learns about A — the property that makes server-free rooms
// actually work for asymmetric join order.
TEST(RoomGossip, LateJoinerSeesPeriodicRepublish) {
    const auto pa = free_port(), pb = free_port();
    auto pub_a = rand_pubkey();
    fb::p2p::P2PNode A("127.0.0.1", pa, pub_a);
    fb::p2p::P2PNode B("127.0.0.1", pb, rand_pubkey());
    A.start(); B.start();
    A.dial("127.0.0.1", pb);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::array<std::uint8_t, 32> room_id{};
    for (std::size_t i = 0; i < room_id.size(); ++i) room_id[i] = 0xc3;
    const std::string topic = fb::p2p::room_topic_name(
        std::span<const std::uint8_t>(room_id.data(), room_id.size()));

    auto publish_a = [&]() {
        fb::proto::Frame beacon;
        auto* m = beacon.mutable_room_roster();
        m->set_room_id(std::string(room_id.begin(), room_id.end()));
        auto* mem = m->add_participants();
        mem->set_identity_pubkey(std::string(pub_a.begin(), pub_a.end()));
        mem->set_has_audio(true);
        std::vector<std::uint8_t> bw(beacon.ByteSizeLong());
        ASSERT_TRUE(beacon.SerializeToArray(bw.data(),
                                              static_cast<int>(bw.size())));
        A.publish(topic, std::span<const std::uint8_t>(bw.data(), bw.size()));
    };

    A.subscribe(topic);
    publish_a();    // first beacon — fires before B is subscribed.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::mutex mu;
    std::condition_variable cv;
    std::atomic_int b_recv_count{0};
    B.set_on_topic_message([&](const std::string& t,
                                 std::span<const std::uint8_t>,
                                 const fb::p2p::PeerInfo&) {
        EXPECT_EQ(t, topic);
        ++b_recv_count;
        cv.notify_all();
    });
    B.subscribe(topic);

    // Mimic the periodic republish loop with a couple of cycles —
    // the production code republishes every 25 s; here we fire
    // tighter so the test isn't slow.
    for (int i = 0; i < 3 && b_recv_count == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        publish_a();
    }
    {
        std::unique_lock lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2),
            [&] { return b_recv_count > 0; }))
            << "late joiner never saw A's republished beacon";
    }
    A.stop(); B.stop();
}

TEST(ChannelGossip, RejectsWrongChannelIdSize) {
    std::vector<std::uint8_t> short_id(31, 0);
    EXPECT_THROW(
        (void)fb::p2p::channel_topic_name(
            std::span<const std::uint8_t>(short_id.data(), short_id.size())),
        std::invalid_argument);
}

// Server-free channel envelope fan-out: 3 nodes, A↔B↔C topology, all
// subscribed to the same channel topic. A publishes a serialized
// Envelope (the same wire shape the central server fans out as
// Frame.envelope); B and C both receive the EXACT bytes via gossip.
//
// This is the proof that channels can fan out without any central
// server — production wiring is "ChatClient.subscribe_now puts
// P2PNode.subscribe(channel_topic_name(...)) alongside the existing
// chan_subscribe Frame".
TEST(ChannelGossip, ThreeNodeChannelEnvelopeDelivery) {
    const auto pa = free_port(), pb = free_port(), pc = free_port();
    fb::p2p::P2PNode A("127.0.0.1", pa, rand_pubkey());
    fb::p2p::P2PNode B("127.0.0.1", pb, rand_pubkey());
    fb::p2p::P2PNode C("127.0.0.1", pc, rand_pubkey());
    A.start(); B.start(); C.start();

    // Linear chain: A ↔ B ↔ C.
    A.dial("127.0.0.1", pb);
    C.dial("127.0.0.1", pb);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::array<std::uint8_t, 32> chan_id{};
    for (std::size_t i = 0; i < chan_id.size(); ++i) {
        chan_id[i] = static_cast<std::uint8_t>(0xa0 + i);
    }
    const std::string topic = fb::p2p::channel_topic_name(
        std::span<const std::uint8_t>(chan_id.data(), chan_id.size()));

    std::mutex mu;
    std::condition_variable cv;
    std::atomic_int recv_count{0};
    std::vector<std::vector<std::uint8_t>> got;
    auto on_msg = [&](const std::string& t,
                       std::span<const std::uint8_t> payload,
                       const fb::p2p::PeerInfo&) {
        EXPECT_EQ(t, topic);
        std::lock_guard lk(mu);
        got.emplace_back(payload.begin(), payload.end());
        ++recv_count;
        cv.notify_all();
    };
    A.set_on_topic_message(on_msg);
    B.set_on_topic_message(on_msg);
    C.set_on_topic_message(on_msg);
    A.subscribe(topic);
    B.subscribe(topic);
    C.subscribe(topic);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Build a wire-form Envelope with arbitrary contents (the
    // payload is opaque to gossip — what matters is byte-equivalence
    // on the receive end).
    fb::proto::Envelope env;
    env.set_envelope_id(std::string(16, 0x42));
    env.set_timestamp_ms(1234567890);
    env.set_aead_alg(1);
    env.set_protocol_version(1);
    env.set_ciphertext(std::string{'h', 'e', 'l', 'l', 'o'});
    env.set_aad(std::string(16, 0x42) + std::string(8, 0x00));
    env.set_channel_group_id(
        std::string(chan_id.begin(), chan_id.end()));

    std::vector<std::uint8_t> payload(env.ByteSizeLong());
    ASSERT_TRUE(env.SerializeToArray(payload.data(),
                                       static_cast<int>(payload.size())));

    A.publish(topic, std::span<const std::uint8_t>(
        payload.data(), payload.size()));

    // Expect at least 2 receivers (B + C). A may also receive its
    // own publish depending on gossip implementation.
    {
        std::unique_lock lk(mu);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(2),
            [&] { return recv_count >= 2; }))
            << "expected at least 2 receivers (B + C); got "
            << recv_count;
    }
    for (const auto& g : got) {
        EXPECT_EQ(g, payload);
        // Re-parse to verify it's still a valid Envelope on the
        // receive side (no truncation/corruption in transit).
        fb::proto::Envelope rcv;
        ASSERT_TRUE(rcv.ParseFromArray(g.data(),
                                         static_cast<int>(g.size())));
        EXPECT_EQ(rcv.envelope_id(), env.envelope_id());
        EXPECT_EQ(rcv.channel_group_id(),
                  std::string(chan_id.begin(), chan_id.end()));
    }
    A.stop(); B.stop(); C.stop();
}
