// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// DhtNode — Kademlia-style routing + provider-record push/pull.
//
// Marries the existing routing primitives (RoutingTable, NodeId,
// node_id_from_pubkey) with the in-memory provider record store. Adds the
// inter-peer messaging needed to DISTRIBUTE records across the swarm:
//
//   publish(record) — sender locates the K peers in its routing table
//     closest to SHA-256(record.publisher_pubkey)[0..20] and sends a
//     DhtPublish to each. Those peers store the record locally; future
//     lookups against any one of them will return it.
//
//   lookup(target_pubkey, on_results) — sender locates the K closest
//     peers to SHA-256(target_pubkey)[0..20] in its routing table, sends
//     each a DhtLookup, and aggregates the ProviderLookupResponse
//     replies via the on_results callback. Plus any records it has
//     locally stored for target_pubkey.
//
//   on_message(from_peer, wire_bytes) — single entry point for inbound
//     DhtMessage envelopes. Dispatches publish (store) / lookup
//     (respond) / response (deliver to pending lookup).
//
// Transport-agnostic: the SendCallback is supplied by the caller. The
// FinBit-Phase-5 plan wires this onto libp2p streams; tests use an
// in-process bridge (DhtNode A's send delivers to DhtNode B's
// on_message and vice-versa).
//
// Threading: single-threaded. Wrap externally if needed.
// =============================================================================

#include "fb/p2p/kademlia.hpp"
#include "fb/p2p/provider_records.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace fb::proto { class ProviderRecord; class PrekeyRecord; class DhtMessage; }

namespace fb::p2p {

// How many closest peers we ping for each publish/lookup. Standard
// Kademlia parameter (typically called K). Bounded by RoutingTable's
// kBucketSize, so a value > kBucketSize is silently capped.
constexpr std::size_t kReplicationFactor = 8;

// Outbound transport: deliver `wire_bytes` (a serialized DhtMessage)
// to `peer`. The implementation is responsible for any framing,
// encryption, retries, etc. — this is the seam between DhtNode and
// whatever real transport you've plugged in.
using DhtSendCallback =
    std::function<void(const PeerInfo& peer,
                       std::span<const std::uint8_t> wire_bytes)>;

// Lookup result callback. Fires once per unique record gathered (from
// our local store + each responding peer). Same record arriving from
// multiple peers fires the callback ONCE (deduped on
// publisher_pubkey || nonce).
using DhtLookupCallback =
    std::function<void(const std::vector<fb::proto::ProviderRecord>&)>;

using DhtPrekeyLookupCallback =
    std::function<void(const std::vector<fb::proto::PrekeyRecord>&)>;

class DhtNode {
public:
    DhtNode(NodeId self, DhtSendCallback send);
    ~DhtNode();
    DhtNode(const DhtNode&)            = delete;
    DhtNode& operator=(const DhtNode&) = delete;

    // Add a peer to the routing table. Caller is responsible for
    // figuring out HOW to talk to peers (the PeerInfo.addr field
    // is opaque to DhtNode; the SendCallback knows how to interpret).
    void observe(const PeerInfo& peer);

    // Self-publish: stores `record` locally AND sends DhtPublish to
    // the kReplicationFactor peers in our routing table closest to
    // SHA-256(record.publisher_pubkey)[0..20]. Caller-side validation
    // happens before send (build_record + ProviderStore::put accept
    // the record on our side too); rejected by put → no broadcast.
    // Returns the number of remote peers we sent to (may be 0 if
    // the routing table is empty).
    std::size_t publish(const fb::proto::ProviderRecord& record);

    // Issue a lookup. Returns IMMEDIATELY with whatever's in the
    // local store; sends DhtLookup to the K closest routing-table
    // peers and invokes `on_results` again as their responses arrive.
    // If the routing table is empty, no remote queries are sent and
    // only local results fire.
    //
    // The callback may fire MULTIPLE times — once for the local
    // batch, then once per responding peer with cumulative deduped
    // results (each call carries everything seen so far). Caller
    // can ignore later calls if they only want the first hit.
    //
    // The lookup's outstanding state is freed when (a) every
    // queried peer has replied, or (b) call_lookup_timeout(...) is
    // invoked with the request_id. No automatic timer — callers
    // wire timeouts via their own loop.
    std::size_t lookup(std::span<const std::uint8_t> target_pubkey,
                       DhtLookupCallback on_results);

    // Single inbound dispatch entry. Parses wire_bytes as a
    // DhtMessage and routes by oneof body. Unknown / malformed
    // messages are silently dropped (logged via emit() in a
    // future revision).
    void on_message(const PeerInfo& from_peer,
                    std::span<const std::uint8_t> wire_bytes);

    // Clear the in-flight state for a lookup that timed out so
    // the response slot is reclaimed.
    void abort_lookup(std::span<const std::uint8_t> request_id);

    // ---- Prekey bundle publish + lookup (X3DH without a server) ----

    // Self-publish a prekey bundle. Stored locally and broadcast to
    // the K closest peers so DM-initiators can find us via DHT.
    std::size_t publish_prekey(const fb::proto::PrekeyRecord& record);

    // Issue a prekey lookup. Local hits fire first; remote responses
    // fire as they arrive (cumulative dedup, same shape as lookup()).
    std::size_t lookup_prekey(std::span<const std::uint8_t> target_pubkey,
                                DhtPrekeyLookupCallback on_results);

    void abort_prekey_lookup(std::span<const std::uint8_t> request_id);

    // Diagnostics / test plumbing.
    [[nodiscard]] RoutingTable&  routing()         { return routing_; }
    [[nodiscard]] ProviderStore& store()           { return store_; }
    [[nodiscard]] PrekeyStore&   prekeys()         { return prekeys_; }
    [[nodiscard]] std::size_t    pending_lookups() const;
    [[nodiscard]] std::size_t    pending_prekey_lookups() const;

private:
    struct Impl;
    NodeId                          self_;
    DhtSendCallback                 send_;
    RoutingTable                    routing_;
    ProviderStore                   store_;
    PrekeyStore                     prekeys_;
    std::unique_ptr<Impl>           impl_;
};

}  // namespace fb::p2p
