// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/identity/username_gossip.hpp"

#include "fb/identity/username_log.hpp"
#include "fb/p2p/kademlia.hpp"   // PeerInfo

#include <sodium.h>

#include "identity_log.pb.h"

#include <cstring>
#include <stdexcept>

namespace fb::identity {

namespace {

std::vector<std::uint8_t> serialize_msg(
    const fb::proto::IdentityGossipMessage& m) {
    std::vector<std::uint8_t> out(m.ByteSizeLong());
    if (!m.SerializeToArray(out.data(), static_cast<int>(out.size()))) {
        out.clear();
    }
    return out;
}

std::vector<std::uint8_t> fresh_request_id() {
    std::vector<std::uint8_t> id(16);
    randombytes_buf(id.data(), id.size());
    return id;
}

}  // namespace

struct UsernameGossip::Impl {
    std::size_t accepted_count = 0;
};

UsernameGossip::UsernameGossip(UsernameLog& log, GossipSendCallback send)
    : log_(log)
    , send_(std::move(send))
    , impl_(std::make_unique<Impl>()) {}

UsernameGossip::~UsernameGossip() = default;

std::vector<std::uint8_t> UsernameGossip::sync_with(
    const fb::p2p::PeerInfo& peer, std::uint64_t since_ms) {
    auto rid = fresh_request_id();
    fb::proto::IdentityGossipMessage msg;
    auto* req = msg.mutable_request();
    req->set_since_timestamp_ms(since_ms);
    req->set_max_records(static_cast<std::uint32_t>(kClaimsPageMax));
    msg.set_request_id(std::string(rid.begin(), rid.end()));
    auto wire = serialize_msg(msg);
    send_(peer, std::span<const std::uint8_t>(wire.data(), wire.size()));
    return rid;
}

void UsernameGossip::on_message(const fb::p2p::PeerInfo& from_peer,
                                  std::span<const std::uint8_t> wire_bytes) {
    fb::proto::IdentityGossipMessage msg;
    if (!msg.ParseFromArray(wire_bytes.data(),
                             static_cast<int>(wire_bytes.size()))) {
        return;
    }
    switch (msg.body_case()) {
        case fb::proto::IdentityGossipMessage::kRequest: {
            const auto& req = msg.request();
            const std::size_t want_max =
                req.max_records() > 0
                    ? std::min<std::size_t>(req.max_records(), kClaimsPageMax)
                    : kClaimsPageMax;
            auto claims = log_.claims_since(req.since_timestamp_ms(),
                                              want_max + 1);
            const bool truncated = claims.size() > want_max;
            if (truncated) claims.pop_back();   // we asked for +1 to detect

            fb::proto::IdentityGossipMessage reply;
            auto* resp = reply.mutable_response();
            std::uint64_t max_seen = req.since_timestamp_ms();
            for (auto& c : claims) {
                if (c.timestamp_ms() > max_seen) max_seen = c.timestamp_ms();
                *resp->add_claims() = c;
            }
            resp->set_truncated(truncated);
            resp->set_max_seen_ms(max_seen);
            resp->set_request_id(msg.request_id());
            // Mirror the top-level request_id too so callers that
            // dispatch on the envelope (rather than the inner field)
            // still correlate.
            reply.set_request_id(msg.request_id());

            auto wire = serialize_msg(reply);
            send_(from_peer, std::span<const std::uint8_t>(
                wire.data(), wire.size()));
            break;
        }
        case fb::proto::IdentityGossipMessage::kResponse: {
            const auto& resp = msg.response();
            for (const auto& c : resp.claims()) {
                const auto r = log_.append_claim(c);
                if (r == UsernameLog::AppendResult::kAccepted) {
                    ++impl_->accepted_count;
                }
                // Format/sig/clock failures are silently dropped —
                // misbehaving / out-of-sync peers can't poison our
                // log this way.
            }
            break;
        }
        default:
            break;
    }
}

std::size_t UsernameGossip::accepted_via_gossip() const noexcept {
    return impl_->accepted_count;
}

}  // namespace fb::identity
