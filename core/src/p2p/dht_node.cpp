// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/p2p/dht_node.hpp"

#include <sodium.h>

#include "dht.pb.h"

#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>

namespace fb::p2p {

namespace {

// Stable string key for record dedup across multiple peer responses.
// pubkey || nonce uniquely identifies a record (different nonces from
// the same publisher are different records — multi-homed re-publish).
std::string record_key(const fb::proto::ProviderRecord& r) {
    std::string out;
    out.reserve(r.publisher_pubkey().size() + r.nonce().size());
    out.append(r.publisher_pubkey());
    out.append(r.nonce());
    return out;
}
std::string prekey_record_key(const fb::proto::PrekeyRecord& r) {
    std::string out;
    out.reserve(r.publisher_pubkey().size() + r.nonce().size());
    out.append(r.publisher_pubkey());
    out.append(r.nonce());
    return out;
}

std::vector<std::uint8_t> serialize_msg(const fb::proto::DhtMessage& m) {
    std::vector<std::uint8_t> out(m.ByteSizeLong());
    if (!m.SerializeToArray(out.data(),
                             static_cast<int>(out.size()))) {
        out.clear();
    }
    return out;
}

std::array<std::uint8_t, 16> fresh_request_id() {
    std::array<std::uint8_t, 16> id{};
    randombytes_buf(id.data(), id.size());
    return id;
}

// Take up to k closest peers, capped by the routing table's actual K.
std::vector<PeerInfo> closest_capped(const RoutingTable& rt,
                                       const NodeId& target,
                                       std::size_t k) {
    return rt.closest(target, std::min(k, kBucketSize));
}

}  // namespace

struct DhtNode::Impl {
    // Active provider-record lookups.
    struct PendingLookup {
        std::vector<std::uint8_t>             target_pubkey;
        DhtLookupCallback                     callback;
        std::size_t                           awaiting_replies = 0;
        std::map<std::string,
                 fb::proto::ProviderRecord>   seen;
    };
    std::map<std::string, PendingLookup> pending;

    // Active prekey-bundle lookups.
    struct PendingPrekey {
        std::vector<std::uint8_t>             target_pubkey;
        DhtPrekeyLookupCallback               callback;
        std::size_t                           awaiting_replies = 0;
        std::map<std::string,
                 fb::proto::PrekeyRecord>     seen;
    };
    std::map<std::string, PendingPrekey> pending_prekey;
};

DhtNode::DhtNode(NodeId self, DhtSendCallback send)
    : self_(self)
    , send_(std::move(send))
    , routing_(self)
    , impl_(std::make_unique<Impl>()) {}

DhtNode::~DhtNode() = default;

void DhtNode::observe(const PeerInfo& peer) {
    routing_.observe(peer);
}

std::size_t DhtNode::publish(const fb::proto::ProviderRecord& record) {
    // 1. Store locally — we ARE one of the providers, after all.
    //    Skip on rejection (bad sig / format / clock); a record we
    //    can't accept ourselves is useless to gossip.
    const auto local = store_.put(record);
    if (local != ProviderStore::PutResult::kAccepted &&
        local != ProviderStore::PutResult::kAlreadyKnown) {
        return 0;
    }

    if (record.publisher_pubkey().size() != 32) return 0;
    auto target = node_id_from_pubkey(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(
            record.publisher_pubkey().data()),
        record.publisher_pubkey().size()));

    // 2. Locate the K closest peers in our routing table and send
    //    DhtPublish to each. Avoid sending to ourselves (the routing
    //    table omits self anyway, so this is just defense-in-depth).
    auto peers = closest_capped(routing_, target, kReplicationFactor);
    if (peers.empty()) return 0;

    fb::proto::DhtMessage msg;
    *msg.mutable_publish()->mutable_record() = record;
    auto wire = serialize_msg(msg);

    std::size_t sent = 0;
    for (const auto& p : peers) {
        if (p.id == self_) continue;
        send_(p, std::span<const std::uint8_t>(wire.data(), wire.size()));
        ++sent;
    }
    return sent;
}

std::size_t DhtNode::lookup(std::span<const std::uint8_t> target_pubkey,
                              DhtLookupCallback on_results) {
    if (target_pubkey.size() != 32) return 0;
    auto target_node = node_id_from_pubkey(target_pubkey);
    auto peers = closest_capped(routing_, target_node, kReplicationFactor);

    // 1. Local hits first. Always fire the callback even if empty —
    //    callers depend on that to know "lookup complete with N
    //    results so far". If nothing else is in flight, this is the
    //    only fire.
    auto local_hits = store_.get(target_pubkey);

    if (peers.empty()) {
        // Nothing to query remotely; deliver local hits and return.
        on_results(local_hits);
        return 0;
    }

    // 2. Track the in-flight state so responses can correlate.
    auto rid_arr = fresh_request_id();
    std::string rid(rid_arr.begin(), rid_arr.end());
    Impl::PendingLookup pl;
    pl.target_pubkey.assign(target_pubkey.begin(), target_pubkey.end());
    pl.callback = std::move(on_results);
    pl.awaiting_replies = peers.size();
    for (const auto& r : local_hits) {
        pl.seen[record_key(r)] = r;
    }
    // Fire local-batch results before sending requests so the caller
    // sees something even on an unreachable network.
    {
        std::vector<fb::proto::ProviderRecord> snapshot;
        snapshot.reserve(pl.seen.size());
        for (const auto& [_k, v] : pl.seen) snapshot.push_back(v);
        pl.callback(snapshot);
    }
    impl_->pending.emplace(rid, std::move(pl));

    // 3. Fan out the lookup.
    fb::proto::DhtMessage msg;
    auto* lk = msg.mutable_lookup();
    lk->set_target_pubkey(std::string(target_pubkey.begin(),
                                       target_pubkey.end()));
    lk->set_request_id(rid);
    auto wire = serialize_msg(msg);

    std::size_t sent = 0;
    for (const auto& p : peers) {
        if (p.id == self_) continue;
        send_(p, std::span<const std::uint8_t>(wire.data(), wire.size()));
        ++sent;
    }
    return sent;
}

void DhtNode::on_message(const PeerInfo& from_peer,
                           std::span<const std::uint8_t> wire_bytes) {
    fb::proto::DhtMessage msg;
    if (!msg.ParseFromArray(wire_bytes.data(),
                             static_cast<int>(wire_bytes.size()))) {
        return;   // malformed; silently drop
    }
    // Touch the routing table on every inbound — keeps active peers
    // fresh (LRU eviction in RoutingTable favors recently-seen).
    routing_.observe(from_peer);

    switch (msg.body_case()) {
        case fb::proto::DhtMessage::kPublish: {
            // Validate + store. ProviderStore checks the signature
            // and clock; bad records are silently dropped (no point
            // bouncing back an error to a misbehaving peer).
            const auto& rec = msg.publish().record();
            (void)store_.put(rec);
            break;
        }
        case fb::proto::DhtMessage::kLookup: {
            const auto& q = msg.lookup();
            if (q.target_pubkey().size() != 32) return;
            auto pub = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(
                    q.target_pubkey().data()),
                q.target_pubkey().size());
            auto records = store_.get(pub);
            fb::proto::DhtMessage reply;
            auto* resp = reply.mutable_response();
            resp->set_request_id(q.request_id());
            for (const auto& r : records) {
                *resp->add_records() = r;
            }
            auto wire = serialize_msg(reply);
            send_(from_peer, std::span<const std::uint8_t>(
                wire.data(), wire.size()));
            break;
        }
        case fb::proto::DhtMessage::kResponse: {
            const auto& resp = msg.response();
            const std::string rid(resp.request_id());
            auto it = impl_->pending.find(rid);
            if (it == impl_->pending.end()) return;
            auto& pl = it->second;
            for (const auto& r : resp.records()) {
                if (r.publisher_pubkey() !=
                    std::string(pl.target_pubkey.begin(),
                                 pl.target_pubkey.end())) {
                    continue;
                }
                pl.seen[record_key(r)] = r;
                (void)store_.put(r);
            }
            std::vector<fb::proto::ProviderRecord> snapshot;
            snapshot.reserve(pl.seen.size());
            for (const auto& [_k, v] : pl.seen) snapshot.push_back(v);
            pl.callback(snapshot);
            if (pl.awaiting_replies > 0) --pl.awaiting_replies;
            if (pl.awaiting_replies == 0) impl_->pending.erase(it);
            break;
        }
        case fb::proto::DhtMessage::kPrekeyPublish: {
            const auto& rec = msg.prekey_publish().record();
            (void)prekeys_.put(rec);
            break;
        }
        case fb::proto::DhtMessage::kPrekeyLookup: {
            const auto& q = msg.prekey_lookup();
            if (q.target_pubkey().size() != 32) return;
            auto pub = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(
                    q.target_pubkey().data()),
                q.target_pubkey().size());
            auto records = prekeys_.get_all(pub);
            fb::proto::DhtMessage reply;
            auto* resp = reply.mutable_prekey_response();
            resp->set_request_id(q.request_id());
            for (const auto& r : records) *resp->add_records() = r;
            auto wire = serialize_msg(reply);
            send_(from_peer, std::span<const std::uint8_t>(
                wire.data(), wire.size()));
            break;
        }
        case fb::proto::DhtMessage::kPrekeyResponse: {
            const auto& resp = msg.prekey_response();
            const std::string rid(resp.request_id());
            auto it = impl_->pending_prekey.find(rid);
            if (it == impl_->pending_prekey.end()) return;
            auto& pp = it->second;
            for (const auto& r : resp.records()) {
                if (r.publisher_pubkey() !=
                    std::string(pp.target_pubkey.begin(),
                                 pp.target_pubkey.end())) {
                    continue;
                }
                pp.seen[prekey_record_key(r)] = r;
                (void)prekeys_.put(r);
            }
            std::vector<fb::proto::PrekeyRecord> snapshot;
            snapshot.reserve(pp.seen.size());
            for (const auto& [_k, v] : pp.seen) snapshot.push_back(v);
            pp.callback(snapshot);
            if (pp.awaiting_replies > 0) --pp.awaiting_replies;
            if (pp.awaiting_replies == 0) impl_->pending_prekey.erase(it);
            break;
        }
        default:
            break;
    }
}

void DhtNode::abort_lookup(std::span<const std::uint8_t> request_id) {
    impl_->pending.erase(std::string(
        reinterpret_cast<const char*>(request_id.data()),
        request_id.size()));
}

std::size_t DhtNode::pending_lookups() const {
    return impl_->pending.size();
}

// =============================================================================
// Prekey publish / lookup. Same shape as the provider-record path
// above — different store, different message variants.
// =============================================================================

std::size_t DhtNode::publish_prekey(const fb::proto::PrekeyRecord& record) {
    const auto local = prekeys_.put(record);
    if (local != PrekeyStore::PutResult::kAccepted &&
        local != PrekeyStore::PutResult::kAlreadyKnown) {
        return 0;
    }
    if (record.publisher_pubkey().size() != 32) return 0;
    auto target = node_id_from_pubkey(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(
            record.publisher_pubkey().data()),
        record.publisher_pubkey().size()));
    auto peers = closest_capped(routing_, target, kReplicationFactor);
    if (peers.empty()) return 0;

    fb::proto::DhtMessage msg;
    *msg.mutable_prekey_publish()->mutable_record() = record;
    auto wire = serialize_msg(msg);

    std::size_t sent = 0;
    for (const auto& p : peers) {
        if (p.id == self_) continue;
        send_(p, std::span<const std::uint8_t>(wire.data(), wire.size()));
        ++sent;
    }
    return sent;
}

std::size_t DhtNode::lookup_prekey(std::span<const std::uint8_t> target_pubkey,
                                     DhtPrekeyLookupCallback on_results) {
    if (target_pubkey.size() != 32) return 0;
    auto target_node = node_id_from_pubkey(target_pubkey);
    auto peers = closest_capped(routing_, target_node, kReplicationFactor);

    auto local_hits = prekeys_.get_all(target_pubkey);
    if (peers.empty()) {
        on_results(local_hits);
        return 0;
    }

    auto rid_arr = fresh_request_id();
    std::string rid(rid_arr.begin(), rid_arr.end());
    Impl::PendingPrekey pp;
    pp.target_pubkey.assign(target_pubkey.begin(), target_pubkey.end());
    pp.callback = std::move(on_results);
    pp.awaiting_replies = peers.size();
    for (const auto& r : local_hits) {
        pp.seen[prekey_record_key(r)] = r;
    }
    {
        std::vector<fb::proto::PrekeyRecord> snapshot;
        snapshot.reserve(pp.seen.size());
        for (const auto& [_k, v] : pp.seen) snapshot.push_back(v);
        pp.callback(snapshot);
    }
    impl_->pending_prekey.emplace(rid, std::move(pp));

    fb::proto::DhtMessage msg;
    auto* lk = msg.mutable_prekey_lookup();
    lk->set_target_pubkey(std::string(target_pubkey.begin(),
                                       target_pubkey.end()));
    lk->set_request_id(rid);
    auto wire = serialize_msg(msg);

    std::size_t sent = 0;
    for (const auto& p : peers) {
        if (p.id == self_) continue;
        send_(p, std::span<const std::uint8_t>(wire.data(), wire.size()));
        ++sent;
    }
    return sent;
}

void DhtNode::abort_prekey_lookup(std::span<const std::uint8_t> request_id) {
    impl_->pending_prekey.erase(std::string(
        reinterpret_cast<const char*>(request_id.data()),
        request_id.size()));
}

std::size_t DhtNode::pending_prekey_lookups() const {
    return impl_->pending_prekey.size();
}

}  // namespace fb::p2p
