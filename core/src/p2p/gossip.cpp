// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/gossip.hpp"

#if defined(_WIN32)
#  error "gossip.cpp uses sys/epoll directly. Windows port required: \
factor the epoll calls behind fb::net::IoLoop (which is already the \
shared abstraction) and let IoLoop provide a Win32 backend. \
Tracked in docs/windows-port-status.md."
#endif

#include <sodium.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "fb/net/frame_codec.hpp"
#include "fb/net/io_loop.hpp"
#include "fb/net/tcp.hpp"
#include "p2p.pb.h"

namespace fb::p2p {
namespace {

constexpr std::size_t kSeenMessageCap = 4096;

std::vector<std::uint8_t> serialize(const google::protobuf::MessageLite& m) {
    std::vector<std::uint8_t> out(m.ByteSizeLong());
    if (!m.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}

}  // namespace

struct PeerConn {
    fb::net::Socket sock;
    fb::net::FrameDecoder dec;
    std::vector<std::uint8_t> write_buf;
    PeerInfo peer;       // populated after Ping/Pong handshake
    bool peer_known = false;
    bool outbound = false;
    std::string remote_addr;  // "ip:port"
};

struct P2PNode::Impl {
    Impl(const std::string& bh, std::uint16_t p, std::span<const std::uint8_t> pubkey)
        : bind_host(bh), port(p), self_id(node_id_from_pubkey(pubkey)), table(self_id) {}

    std::string bind_host;
    std::uint16_t port;
    NodeId self_id;
    RoutingTable table;
    std::string self_addr;  // "ip:port" advertised to peers

    fb::net::IoLoop loop;
    fb::net::Socket listener;
    std::atomic_bool running{false};
    std::thread worker;

    mutable std::mutex mu;
    // fd -> conn
    std::unordered_map<int, std::shared_ptr<PeerConn>> conns;
    // node-id -> fd (most recent)
    std::map<NodeId, int> id_to_fd;
    // local subscriptions
    std::set<std::string> my_topics;
    // remote subscriptions: topic -> set<NodeId>
    std::unordered_map<std::string, std::set<NodeId>> topic_subs;
    // dedup of seen message ids
    std::deque<std::string> seen_order;
    std::unordered_set<std::string> seen_set;

    OnTopicMessage on_topic;
    CarryGuard carry_guard = [](const PeerInfo&, std::uint64_t) { return true; };

    bool seen_recently(const std::string& mid) {
        if (seen_set.count(mid)) return true;
        if (seen_order.size() >= kSeenMessageCap) {
            seen_set.erase(seen_order.front());
            seen_order.pop_front();
        }
        seen_order.push_back(mid);
        seen_set.insert(mid);
        return false;
    }

    PeerInfo self_info() const {
        PeerInfo me;
        me.id = self_id;
        me.addr = self_addr;
        return me;
    }

    void enqueue(PeerConn& c, const std::vector<std::uint8_t>& payload) {
        auto framed = fb::net::encode_frame(
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        c.write_buf.insert(c.write_buf.end(), framed.begin(), framed.end());
        loop.mod_fd(c.sock.fd(), EPOLLIN | EPOLLOUT | EPOLLET);
    }

    void send_to_all(const std::vector<std::uint8_t>& payload, int except_fd = -1) {
        for (auto& [fd, c] : conns) {
            if (fd == except_fd) continue;
            if (!c->peer_known) continue;
            enqueue(*c, payload);
        }
    }

    void send_handshake(PeerConn& c) {
        fb::proto::P2PMessage m;
        auto* p = m.mutable_ping();
        auto* from = p->mutable_from();
        from->set_node_id(std::string(reinterpret_cast<const char*>(self_id.data()),
                                      self_id.size()));
        from->set_addr(self_addr);
        std::array<std::uint8_t, 16> nonce{};
        randombytes_buf(nonce.data(), nonce.size());
        p->set_nonce(std::string(nonce.begin(), nonce.end()));
        enqueue(c, serialize(m));
    }

    void send_my_subscriptions(PeerConn& c) {
        for (const auto& t : my_topics) {
            fb::proto::P2PMessage m;
            auto* s = m.mutable_subscribe();
            *s->mutable_from() = [&]() {
                fb::proto::PeerInfo me;
                me.set_node_id(std::string(reinterpret_cast<const char*>(self_id.data()),
                                           self_id.size()));
                me.set_addr(self_addr);
                return me;
            }();
            s->set_topic(t);
            enqueue(c, serialize(m));
        }
    }

    PeerInfo from_proto(const fb::proto::PeerInfo& p) const {
        PeerInfo out;
        if (p.node_id().size() == kNodeIdBytes) {
            std::memcpy(out.id.data(), p.node_id().data(), kNodeIdBytes);
        }
        out.addr = p.addr();
        return out;
    }

    void on_handshake_observed(PeerConn& c, const PeerInfo& peer) {
        c.peer = peer;
        c.peer_known = true;
        id_to_fd[peer.id] = c.sock.fd();
        table.observe(peer);
        // Tell them what we subscribe to.
        send_my_subscriptions(c);
    }

    void handle_frame(PeerConn& c, std::span<const std::uint8_t> bytes) {
        fb::proto::P2PMessage m;
        if (!m.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) return;
        switch (m.body_case()) {
            case fb::proto::P2PMessage::kPing: {
                const auto& ping = m.ping();
                auto peer = from_proto(ping.from());
                if (peer.id != self_id) on_handshake_observed(c, peer);
                fb::proto::P2PMessage resp;
                auto* pong = resp.mutable_pong();
                auto* from = pong->mutable_from();
                from->set_node_id(std::string(reinterpret_cast<const char*>(self_id.data()),
                                              self_id.size()));
                from->set_addr(self_addr);
                pong->set_nonce(ping.nonce());
                enqueue(c, serialize(resp));
                break;
            }
            case fb::proto::P2PMessage::kPong: {
                const auto& pong = m.pong();
                auto peer = from_proto(pong.from());
                if (peer.id != self_id) on_handshake_observed(c, peer);
                break;
            }
            case fb::proto::P2PMessage::kFindNode: {
                const auto& fn = m.find_node();
                auto from = from_proto(fn.from());
                if (from.id != self_id) table.observe(from);
                if (fn.target_node_id().size() != kNodeIdBytes) break;
                NodeId tgt{};
                std::memcpy(tgt.data(), fn.target_node_id().data(), kNodeIdBytes);
                auto closest = table.closest(tgt, kBucketSize);
                fb::proto::P2PMessage resp;
                auto* fr = resp.mutable_find_node_resp();
                auto* me = fr->mutable_from();
                me->set_node_id(std::string(reinterpret_cast<const char*>(self_id.data()),
                                            self_id.size()));
                me->set_addr(self_addr);
                for (const auto& p : closest) {
                    auto* pp = fr->add_peers();
                    pp->set_node_id(std::string(reinterpret_cast<const char*>(p.id.data()),
                                                p.id.size()));
                    pp->set_addr(p.addr);
                }
                enqueue(c, serialize(resp));
                break;
            }
            case fb::proto::P2PMessage::kFindNodeResp: {
                const auto& fr = m.find_node_resp();
                auto from = from_proto(fr.from());
                if (from.id != self_id) table.observe(from);
                for (const auto& p : fr.peers()) {
                    auto pi = from_proto(p);
                    if (pi.id != self_id) table.observe(pi);
                }
                break;
            }
            case fb::proto::P2PMessage::kSubscribe: {
                const auto& s = m.subscribe();
                auto peer = from_proto(s.from());
                if (peer.id == self_id) break;
                topic_subs[s.topic()].insert(peer.id);
                table.observe(peer);
                break;
            }
            case fb::proto::P2PMessage::kUnsubscribe: {
                const auto& u = m.unsubscribe();
                auto peer = from_proto(u.from());
                auto it = topic_subs.find(u.topic());
                if (it != topic_subs.end()) it->second.erase(peer.id);
                break;
            }
            case fb::proto::P2PMessage::kPublish: {
                const auto& p = m.publish();
                if (p.message_id().empty()) break;
                if (seen_recently(p.message_id())) break;
                auto from = from_proto(p.from());
                // Deliver locally if subscribed.
                if (my_topics.count(p.topic()) && on_topic) {
                    on_topic(p.topic(),
                             std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(p.payload().data()),
                                 p.payload().size()),
                             from);
                }
                // Relay to other peers if TTL allows.
                if (p.ttl() == 0) break;
                fb::proto::P2PMessage forwarded = m;
                forwarded.mutable_publish()->set_ttl(p.ttl() - 1);
                auto bytes_out = serialize(forwarded);
                for (auto& [fd, conn] : conns) {
                    if (fd == c.sock.fd()) continue;
                    if (!conn->peer_known) continue;
                    if (conn->peer.id == from.id) continue;
                    if (!carry_guard(conn->peer, bytes_out.size())) continue;
                    enqueue(*conn, bytes_out);
                }
                break;
            }
            default:
                break;
        }
    }

    void on_conn_event(int fd, std::uint32_t events) {
        std::shared_ptr<PeerConn> c;
        {
            std::lock_guard lk(mu);
            auto it = conns.find(fd);
            if (it == conns.end()) return;
            c = it->second;
        }
        if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            close_conn(fd);
            return;
        }
        if (events & EPOLLIN) {
            std::array<std::uint8_t, 4096> buf;
            for (;;) {
                auto n = c->sock.read_some(std::span<std::uint8_t>(buf.data(), buf.size()));
                if (n == fb::net::Socket::kReadRetry) break;
                if (n <= 0) {                                       // 0 = EOF, -1 = error
                    close_conn(fd);
                    return;
                }
                c->dec.feed(std::span<const std::uint8_t>(buf.data(),
                                                          static_cast<std::size_t>(n)));
                std::vector<std::uint8_t> frame;
                fb::net::FrameDecoder::Status st;
                while ((st = c->dec.try_pop(frame)) == fb::net::FrameDecoder::Status::kFrameReady) {
                    std::lock_guard lk(mu);
                    handle_frame(*c, std::span<const std::uint8_t>(frame.data(), frame.size()));
                }
                if (st == fb::net::FrameDecoder::Status::kError) {
                    close_conn(fd);
                    return;
                }
                if (static_cast<std::size_t>(n) < buf.size()) break;
            }
        }
        if (events & EPOLLOUT) {
            std::lock_guard lk(mu);
            while (!c->write_buf.empty()) {
                auto n = c->sock.write_some(
                    std::span<const std::uint8_t>(c->write_buf.data(), c->write_buf.size()));
                if (n < 0) {
                    close_conn(fd);
                    return;
                }
                if (n == 0) break;
                c->write_buf.erase(c->write_buf.begin(), c->write_buf.begin() + n);
            }
            const std::uint32_t want = c->write_buf.empty() ? (EPOLLIN | EPOLLET)
                                                            : (EPOLLIN | EPOLLOUT | EPOLLET);
            loop.mod_fd(fd, want);
        }
    }

    void close_conn(int fd) {
        std::lock_guard lk(mu);
        auto it = conns.find(fd);
        if (it == conns.end()) return;
        if (it->second->peer_known) {
            auto idit = id_to_fd.find(it->second->peer.id);
            if (idit != id_to_fd.end() && idit->second == fd) id_to_fd.erase(idit);
        }
        loop.remove_fd(fd);
        conns.erase(it);
    }

    void register_conn(std::shared_ptr<PeerConn> conn) {
        const int fd = conn->sock.fd();
        {
            std::lock_guard lk(mu);
            conns[fd] = conn;
        }
        loop.add_fd(fd, EPOLLIN | EPOLLET, [this](int f, std::uint32_t e) { on_conn_event(f, e); });
        // Send our hello.
        std::lock_guard lk(mu);
        send_handshake(*conn);
    }
};

P2PNode::P2PNode(const std::string& bind_host, std::uint16_t port,
                 std::span<const std::uint8_t> pubkey)
    : impl_(std::make_unique<Impl>(bind_host, port, pubkey)) {}

P2PNode::~P2PNode() { stop(); }

void P2PNode::start() {
    if (impl_->running.exchange(true)) return;
    impl_->listener = fb::net::tcp_listen(impl_->bind_host, impl_->port);
    impl_->self_addr = impl_->bind_host + ":" + std::to_string(impl_->port);
    impl_->loop.add_fd(impl_->listener.fd(), EPOLLIN, [this](int lfd, std::uint32_t) {
        for (;;) {
            auto s = fb::net::tcp_accept(lfd);
            if (!s.valid()) break;
            auto conn = std::make_shared<PeerConn>();
            conn->sock = std::move(s);
            conn->outbound = false;
            impl_->register_conn(conn);
        }
    });
    impl_->worker = std::thread([this]() { impl_->loop.run(); });
}

void P2PNode::stop() {
    if (!impl_->running.exchange(false)) return;
    impl_->loop.stop();
    if (impl_->worker.joinable()) impl_->worker.join();
}

void P2PNode::dial(const std::string& host, std::uint16_t port) {
    auto sock = fb::net::tcp_connect(host, port);
    auto conn = std::make_shared<PeerConn>();
    conn->sock = std::move(sock);
    conn->outbound = true;
    conn->remote_addr = host + ":" + std::to_string(port);
    impl_->register_conn(conn);
}

void P2PNode::subscribe(const std::string& topic) {
    std::lock_guard lk(impl_->mu);
    impl_->my_topics.insert(topic);
    fb::proto::P2PMessage m;
    auto* s = m.mutable_subscribe();
    auto* from = s->mutable_from();
    from->set_node_id(std::string(reinterpret_cast<const char*>(impl_->self_id.data()),
                                  impl_->self_id.size()));
    from->set_addr(impl_->self_addr);
    s->set_topic(topic);
    impl_->send_to_all(serialize(m));
}

void P2PNode::unsubscribe(const std::string& topic) {
    std::lock_guard lk(impl_->mu);
    impl_->my_topics.erase(topic);
    fb::proto::P2PMessage m;
    auto* u = m.mutable_unsubscribe();
    auto* from = u->mutable_from();
    from->set_node_id(std::string(reinterpret_cast<const char*>(impl_->self_id.data()),
                                  impl_->self_id.size()));
    from->set_addr(impl_->self_addr);
    u->set_topic(topic);
    impl_->send_to_all(serialize(m));
}

void P2PNode::publish(const std::string& topic, std::span<const std::uint8_t> payload,
                      std::uint32_t ttl) {
    std::lock_guard lk(impl_->mu);
    fb::proto::P2PMessage m;
    auto* p = m.mutable_publish();
    auto* from = p->mutable_from();
    from->set_node_id(std::string(reinterpret_cast<const char*>(impl_->self_id.data()),
                                  impl_->self_id.size()));
    from->set_addr(impl_->self_addr);
    p->set_topic(topic);
    std::array<std::uint8_t, 16> mid{};
    randombytes_buf(mid.data(), mid.size());
    p->set_message_id(std::string(mid.begin(), mid.end()));
    p->set_payload(std::string(payload.begin(), payload.end()));
    p->set_ttl(ttl);
    impl_->seen_recently(p->message_id());  // mark our own as seen so we don't re-relay
    impl_->send_to_all(serialize(m));
}

void P2PNode::set_on_topic_message(OnTopicMessage cb) {
    std::lock_guard lk(impl_->mu);
    impl_->on_topic = std::move(cb);
}

void P2PNode::set_carry_guard(CarryGuard guard) {
    std::lock_guard lk(impl_->mu);
    impl_->carry_guard = std::move(guard);
}

std::size_t P2PNode::known_peer_count() const {
    std::lock_guard lk(impl_->mu);
    return impl_->table.size();
}

NodeId P2PNode::node_id() const noexcept { return impl_->self_id; }

std::string P2PNode::addr() const { return impl_->self_addr; }

}  // namespace fb::p2p
