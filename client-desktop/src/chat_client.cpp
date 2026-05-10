// SPDX-License-Identifier: AGPL-3.0-or-later
#include "chat_client.hpp"

#include <sodium.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <QMetaObject>
#include <QString>
#include <algorithm>
#include <array>
#include <atomic>
#include <set>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "dm_payload.pb.h"
#include "envelope.pb.h"
#include "fb/config/build_config.hpp"
#include "fb/crypto/hkdf.hpp"
#include "fb/crypto/identity.hpp"
#include "fb/crypto/ratchet.hpp"
#include "fb/crypto/sender_keys.hpp"
#include "fb/crypto/mls_facade.hpp"
#include "media_call.hpp"
#include "fb/net/frame_codec.hpp"
#include "fb/net/tcp.hpp"
#include "fb/net/tls_client.hpp"
#include "fb/identity/username_gossip.hpp"
#include "fb/identity/username_log.hpp"
#include "fb/p2p/bootstrap.hpp"
#include "fb/p2p/channel_gossip.hpp"
#include "fb/p2p/dht_node.hpp"
#include "fb/p2p/gossip.hpp"
#include "fb/p2p/offline_relay.hpp"
#include "fb/p2p/peer_net.hpp"
#include "fb/p2p/provider_records.hpp"
#include "dht.pb.h"
#include "identity_log.pb.h"
#include "fb/store/sqlite_store.hpp"
#include "handshake.pb.h"
#include "sender_keys.pb.h"

#include <QDir>
#include <QStandardPaths>
#include <filesystem>
#include <fstream>

namespace fb::desktop {
namespace {

constexpr std::string_view kX3dhInfo = "FinBit-X3DH-v0";

struct X25519Pair {
    std::array<std::uint8_t, 32> pub{};
    std::array<std::uint8_t, 32> priv{};
};
X25519Pair derive_x25519(const fb::crypto::Identity& id) {
    X25519Pair k;
    auto sec = id.secret_key();
    if (crypto_sign_ed25519_sk_to_curve25519(k.priv.data(), sec.data()) != 0 ||
        crypto_sign_ed25519_pk_to_curve25519(k.pub.data(), id.public_key().data()) != 0) {
        throw std::runtime_error("ed25519->curve25519 conversion failed");
    }
    return k;
}

std::array<std::uint8_t, 32> derive_shared_secret(const X25519Pair& mine,
                                                  std::span<const std::uint8_t, 32> peer_pub) {
    std::array<std::uint8_t, 32> dh{};
    if (crypto_scalarmult(dh.data(), mine.priv.data(), peer_pub.data()) != 0) {
        throw std::runtime_error("scalarmult low-order");
    }
    auto prk = fb::crypto::hkdf_extract(
        std::span<const std::uint8_t>(),
        std::span<const std::uint8_t>(dh.data(), dh.size()));
    auto vec = fb::crypto::hkdf_expand(prk,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(kX3dhInfo.data()), kX3dhInfo.size()),
        32);
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), vec.data(), 32);
    return out;
}

std::vector<std::uint8_t> serialize(const google::protobuf::MessageLite& m) {
    std::vector<std::uint8_t> out(m.ByteSizeLong());
    if (!m.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}

// Conn — transport-agnostic handle. Holds either a raw Socket OR a
// TlsClient; the rest of chat_client speaks only to Conn so the
// length-prefixed Frame protobufs flow over either transport without
// every call site branching. Same shape as fb-cli's Conn.
struct Conn {
    fb::net::Socket*    sock = nullptr;
    fb::net::TlsClient* tls  = nullptr;

    [[nodiscard]] int fd() const {
        return tls ? tls->fd() : sock->fd();
    }

    void send_all(std::span<const std::uint8_t> data) {
        if (tls) {
            tls->blocking_send_all(data);
            return;
        }
        std::size_t off = 0;
        while (off < data.size()) {
            const auto n = ::send(sock->fd(), data.data() + off,
                                   data.size() - off, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error(std::string("send: ") +
                                          std::strerror(errno));
            }
            off += static_cast<std::size_t>(n);
        }
    }

    // Returns 0 on EOF / clean shutdown / timeout. Mirrors the
    // existing read_some convention used in chat_client.
    std::size_t read_some(std::span<std::uint8_t> out, int timeout_ms) {
        if (tls) return tls->blocking_read(out, timeout_ms);
        timeval tv{};
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(sock->fd(), &rs);
        const int sel = ::select(sock->fd() + 1, &rs, nullptr, nullptr, &tv);
        if (sel <= 0) return 0;
        const auto n = sock->read_some(out);
        if (n <= 0) return 0;
        return static_cast<std::size_t>(n);
    }
};

void blocking_send(Conn& c, const std::vector<std::uint8_t>& payload) {
    auto framed = fb::net::encode_frame(
        std::span<const std::uint8_t>(payload.data(), payload.size()));
    c.send_all(std::span<const std::uint8_t>(framed.data(), framed.size()));
}

// Compatibility helper: read up to `out.size()` bytes from `c`,
// blocking up to `timeout_ms`. Returns 0 on EOF/timeout. Replaces
// the old wait_readable + sock->read_some pair at every call site.
std::size_t conn_read_with_timeout(Conn& c, std::span<std::uint8_t> out,
                                     int timeout_ms) {
    return c.read_some(out, timeout_ms);
}

// Compose the envelope-level AAD that's bound by the inner ratchet /
// SenderKeys AEAD tag — `envelope_id (16) || timestamp_ms (8 BE)`.
// Sender computes this once per envelope, passes it both as
// outer_aad to the inner encrypt AND populates Envelope.aad with the
// SAME bytes; receivers cross-check `env.aad()` against the
// reconstruction, then use it as outer_aad on decrypt. Old (pre-aad-
// binding) clients leave Envelope.aad empty and used empty outer_aad
// — receivers honour that empty value to stay backwards-compatible.
std::vector<std::uint8_t> envelope_aad_bytes(
    std::span<const std::uint8_t> envelope_id, std::uint64_t timestamp_ms) {
    std::vector<std::uint8_t> aad;
    aad.reserve(envelope_id.size() + 8);
    aad.insert(aad.end(), envelope_id.begin(), envelope_id.end());
    for (int sh = 56; sh >= 0; sh -= 8) {
        aad.push_back(static_cast<std::uint8_t>((timestamp_ms >> sh) & 0xff));
    }
    return aad;
}

}  // namespace

struct PendingSend {
    std::string peer;
    std::string text;
    // Optional pre-packed DmPayload bytes — used by MLS handshake
    // sends (mls_invite_request / mls_key_package / mls_welcome /
    // mls_commit) so they ride the same Double Ratchet machinery as
    // regular text DMs without needing a parallel queue. When set,
    // the worker encrypts these bytes verbatim instead of calling
    // pack_text_payload(text). text is left empty in that case.
    std::vector<std::uint8_t> pre_packed_payload;
    bool has_pre_packed() const { return !pre_packed_payload.empty(); }
};

struct PendingChannelOp {
    enum class Kind {
        kCreate, kCreateLocal, kJoin, kSend, kInvite, kLeave,
        kRoomJoin, kRoomLeave
    };
    Kind        kind;
    std::string channel_name;
    std::string dist_path;   // for create / join
    std::string text;        // for send
    std::string peer;        // for invite
    bool        want_video = false;   // for kRoomJoin
    bool        use_mls    = false;   // for kCreateLocal — opt into MLS at create time
};

// Outbound media-signal sends (OFFER/ANSWER/ICE/HANGUP/SFRAME_KEY) get
// queued by peer pubkey rather than by username — MediaCall doesn't know
// or care about usernames; it just talks to the pubkey it was handed.
struct PendingMediaSignal {
    std::array<std::uint8_t, 32> peer_pub{};
    std::array<std::uint8_t, 16> call_id{};
    std::uint32_t kind  = 0;
    std::uint32_t epoch = 0;
    std::vector<std::uint8_t> payload;
};

std::vector<std::uint8_t> pack_text_payload(const std::string& text) {
    fb::proto::DmPayload p;
    p.set_text(text);
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}

QString peer_label_for(std::span<const std::uint8_t> pub) {
    QString s = "peer-";
    for (int i = 0; i < 4 && i < static_cast<int>(pub.size()); ++i) {
        s += QString::asprintf("%02x", pub[i]);
    }
    return s;
}

std::vector<std::uint8_t> pack_media_signal_payload(
    std::span<const std::uint8_t, 16> call_id, std::uint32_t kind,
    std::span<const std::uint8_t> payload, std::uint32_t epoch) {
    fb::proto::DmPayload p;
    auto* ms = p.mutable_media_signal();
    ms->set_call_id(std::string(call_id.begin(), call_id.end()));
    ms->set_kind(kind);
    ms->set_payload(std::string(payload.begin(), payload.end()));
    ms->set_epoch(epoch);
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}

std::vector<std::uint8_t> pack_channel_key_payload(
    std::span<const std::uint8_t> channel_id, const std::string& channel_name,
    std::span<const std::uint8_t> distribution_blob) {
    fb::proto::DmPayload p;
    auto* ck = p.mutable_channel_key();
    ck->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    ck->set_channel_name(channel_name);
    if (!ck->mutable_distribution()->ParseFromArray(
            distribution_blob.data(), static_cast<int>(distribution_blob.size()))) {
        return {};
    }
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}

// MLS handshake packers — wrap each variant in a DmPayload for delivery
// via the existing pairwise Double Ratchet. The four variants are
// individually small (a KeyPackage is ~700B with the X25519 cipher
// suite); they sit alongside ChannelKeyDistribution as in-band channel
// management messages. See dm_payload.proto for the role of each.
std::vector<std::uint8_t> pack_mls_invite_request_payload(
    std::span<const std::uint8_t> channel_id, const std::string& channel_name) {
    fb::proto::DmPayload p;
    auto* m = p.mutable_mls_invite_request();
    m->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    m->set_channel_name(channel_name);
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}
std::vector<std::uint8_t> pack_mls_key_package_payload(
    std::span<const std::uint8_t> channel_id, std::span<const std::uint8_t> kp) {
    fb::proto::DmPayload p;
    auto* m = p.mutable_mls_key_package();
    m->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    m->set_key_package(std::string(kp.begin(), kp.end()));
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}
std::vector<std::uint8_t> pack_mls_welcome_payload(
    std::span<const std::uint8_t> channel_id, const std::string& channel_name,
    std::span<const std::uint8_t> welcome) {
    fb::proto::DmPayload p;
    auto* m = p.mutable_mls_welcome();
    m->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    m->set_channel_name(channel_name);
    m->set_welcome(std::string(welcome.begin(), welcome.end()));
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}
std::vector<std::uint8_t> pack_mls_commit_payload(
    std::span<const std::uint8_t> channel_id, std::span<const std::uint8_t> commit) {
    fb::proto::DmPayload p;
    auto* m = p.mutable_mls_commit();
    m->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    m->set_commit(std::string(commit.begin(), commit.end()));
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}
std::vector<std::uint8_t> pack_mls_proposal_payload(
    std::span<const std::uint8_t> channel_id, std::span<const std::uint8_t> proposal) {
    fb::proto::DmPayload p;
    auto* m = p.mutable_mls_proposal();
    m->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    m->set_proposal(std::string(proposal.begin(), proposal.end()));
    std::vector<std::uint8_t> out(p.ByteSizeLong());
    if (!p.SerializeToArray(out.data(), static_cast<int>(out.size()))) out.clear();
    return out;
}

std::array<std::uint8_t, 32> channel_id_from_name(const std::string& name) {
    std::array<std::uint8_t, 32> id{};
    crypto_generichash(id.data(), id.size(),
                       reinterpret_cast<const std::uint8_t*>(name.data()), name.size(),
                       reinterpret_cast<const std::uint8_t*>("FinBit-Chan"), 11);
    return id;
}

std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>());
}

void write_file_bytes(const std::string& path, std::span<const std::uint8_t> bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

struct ChannelState {
    std::array<std::uint8_t, 32>      id{};
    std::vector<std::uint8_t>         own_dist;       // serialized SenderKeysDistribution
    std::unique_ptr<fb::crypto::GroupSession> session = std::make_unique<fb::crypto::GroupSession>();
    bool                              subscribed = false;
    // Per-channel cipher discriminator. Default stays SenderKeys so
    // existing channels created before MLS landed don't change
    // semantics on restore. New channels can be created with kMls via
    // create_local_channel(name, /*use_mls=*/true).
    fb::store::SqliteStore::ChannelCrypto crypto =
        fb::store::SqliteStore::ChannelCrypto::kSenderKeys;
    // MLS group state when crypto == kMls. In-memory only — mls::Session
    // is reconstructed at process start by replaying the saved
    // operation log against the bootstrap seed (see
    // mls_group_save / mls_group_op_append / mls_group_load on the
    // store). The receive path also gracefully falls back to
    // SenderKeys decrypt when mls is null (e.g. before restore
    // completes).
    std::unique_ptr<fb::crypto::MlsGroup> mls;
    // Next sequence number to use when appending an op for this MLS
    // channel to mls_group_log. Starts at 0 for newly-created groups,
    // bumped after every state-mutating call and after every replayed
    // op on restore.
    std::int64_t mls_next_seq = 0;
    // Joiner-side state when WE are mid-join on this channel (we've
    // received an InviteRequest, replied with our KP, and are waiting
    // for a Welcome). Single-use; complete()d on receipt of the
    // Welcome.
    std::unique_ptr<fb::crypto::PendingMlsJoin> pending_join;
    // Set of OTHER members in this MLS channel as we know them right
    // now (raw 32-byte identity pubkeys; matches what
    // MlsGroup::member_identities returns minus self). Maintained in
    // sync with cs.mls so the orchestration knows where to fan out
    // proposals and commits without re-walking the roster on every
    // send. Refreshed after every add_member / apply_commit.
    std::set<std::string> mls_member_pubs;
};

struct ChatClient::Impl {
    std::atomic_bool running{false};
    std::thread worker;

    std::mutex mu;
    std::condition_variable cv;
    std::deque<PendingSend> queue;
    std::deque<PendingChannelOp> chan_queue;
    std::deque<PendingMediaSignal> media_queue;
    // FIFO of usernames for which we have an in-flight KeyBundleFetch.
    // Tracks both DM-send and channel-invite fetches so the response
    // handler can pop the correct queued op on success/failure (the wire
    // format predates the request_id field on these clients, so we
    // disambiguate by send order).
    std::deque<std::string> pending_fetch_targets;
    bool stop_requested = false;

    QString username;
    QString host;
    std::uint16_t port = 0;
    // 32-byte Ed25519 seed handed in by LoginDialog. Always set before the
    // worker thread starts; cleared after we hand it to Identity::from_seed.
    std::array<std::uint8_t, 32> seed{};

    // Touched by worker only.
    std::optional<fb::crypto::Identity> identity;
    X25519Pair x25519;
    std::unique_ptr<fb::store::SqliteStore> store;
    std::string store_path;
    std::optional<fb::net::Socket> sock;
    std::optional<fb::net::TlsClient> tls;
    Conn conn;            // points at sock or tls; lifetime tied to whichever
    // TLS configuration captured by connect_tls. Empty / false for the
    // legacy connect() path so existing callers see no behaviour
    // change.
    bool        use_tls = false;
    std::string tls_ca_file;
    bool        tls_insecure_skip_verify = false;
    std::string tls_sni;
    fb::net::FrameDecoder dec;
    // Serverless overlay state. Each peer holds its own username log
    // + DHT routing+provider store. Both layers' SendCallbacks wrap
    // outbound messages in Frame.peer + ship via the central server's
    // relay (which sees only opaque, signed payloads). When a true-P2P
    // transport ships, the SendCallbacks get rewired to it without
    // touching DhtNode / UsernameGossip themselves.
    std::unique_ptr<fb::identity::UsernameLog>    username_log;
    std::unique_ptr<fb::identity::UsernameGossip> username_gossip;
    std::unique_ptr<fb::p2p::DhtNode>             dht;
    // Optional direct-P2P transport. Started when the user opts in
    // via env (FB_PEER_LISTEN_PORT + FB_PEER_LISTEN_CERT +
    // FB_PEER_LISTEN_KEY). When configured, wrap_peer_send prefers
    // PeerNet for peers whose addr is dialable (wss://...). Without
    // it, all overlay traffic falls back to the central server's
    // Frame.peer relay path.
    std::unique_ptr<fb::p2p::PeerNet>             peer_net;
    std::string                                    own_p2p_addr; // for self-publish

    // Friend-relay (I4). Each entry is a 32-byte Ed25519 pubkey of a
    // contact this user has designated as an offline relay. Embedded
    // in our own ProviderRecord on every republish; senders facing
    // an unreachable peer fall back to depositing into one of the
    // peer's relays.
    std::vector<std::vector<std::uint8_t>>        own_offline_relays;
    // We ALSO act as a relay for any peers who designated us. Their
    // OFFLINE_DEPOSIT messages land in this store; their
    // OFFLINE_FETCH messages drain it.
    std::unique_ptr<fb::p2p::OfflineRelayStore>   offline_store;

    // I3: optional P2PNode for channel envelopes via gossipsub. Env-
    // controlled like PeerNet (FB_GOSSIP_PORT + FB_GOSSIP_DIAL).
    // When present, ChatClient subscribes to channel topics and
    // gossipsub fans out channel envelopes peer-to-peer alongside
    // (or instead of) the central server's chan_subscribe path.
    std::unique_ptr<fb::p2p::P2PNode>             gossip;

    // Periodic overlay maintenance state.
    std::uint64_t                                  last_self_publish_ms = 0;
    std::uint64_t                                  last_gossip_pull_ms  = 0;
    std::map<std::string, std::uint64_t>           gossip_watermark;  // peer_pub → last sync_with timestamp_ms

    // Inbound queue for messages PeerNet's worker threads push in;
    // drained by the chat_client worker thread so DhtNode /
    // UsernameGossip see all callbacks on the same thread (matches
    // the server-relayed path's threading model).
    std::mutex                                    overlay_inbox_mu;
    struct OverlayInboundMsg {
        std::vector<std::uint8_t> sender_pubkey;   // empty if unknown
        std::vector<std::uint8_t> bytes;            // serialized Frame.peer
    };
    std::deque<OverlayInboundMsg>                 overlay_inbox;
    // peer-username -> (peer pubkey + ratchet state)
    struct Session {
        std::array<std::uint8_t, 32> peer_pub{};
        std::array<std::uint8_t, 32> peer_x{};
        std::optional<fb::crypto::DoubleRatchet> rat;
        bool initialized_as_alice = false;
    };
    std::map<std::string, Session> sessions;
    // Channels keyed by display-name. id is name -> generichash.
    std::map<std::string, ChannelState> channels;
    // Reverse index: channel id (32 bytes as std::string) -> name. So an
    // inbound envelope's channel_group_id can be resolved back.
    std::map<std::string, std::string> chan_id_to_name;

    // Active calls, keyed by peer pubkey (raw 32-byte string). Held by
    // ChatClient (owner thread = Qt main) so the worker thread reads it
    // via Qt signals only — never directly. v0 supports one MediaCall per
    // peer (no glare with the same person), but multiple peers
    // simultaneously — that's what makes mesh channel calls possible.
    struct CallEntry {
        MediaCall*                          call    = nullptr;
        std::array<std::uint8_t, 16>        call_id = {};
        // Optional: room_id this call belongs to (32 raw bytes, empty for
        // 1:1 DM calls). Set when the call was started by mesh-dial on a
        // RoomRoster delta — used by hangup-fanout when leaving a room.
        std::string                         room_id;
    };
    std::map<std::string, CallEntry> calls_by_peer;
    // Per-room set of peer-pubkey strings we've already mesh-dialed (or
    // accepted from). Diffed against incoming RoomRoster broadcasts so
    // re-rosters don't redial existing peers, and departed peers get
    // their MediaCall torn down.
    std::map<std::string /*room_id*/, std::set<std::string /*peer_pub*/>> room_mesh_peers;

    // Lazy session bootstrap for mesh-dial. When the roster surfaces a
    // peer we've never DM'd, we can't immediately encrypt outbound media
    // signals — there's no ratchet session for them yet. The worker
    // queues a username_lookup, then a key_fetch, then re-dispatches
    // start_call_to_pub on the main thread once sessions[username] is
    // populated. Cleans up automatically on success or NOT_FOUND.
    struct PendingMeshDial {
        std::string room_id;
        bool        with_video;
        QString     label;
    };
    // Keyed by 32-byte peer pubkey (raw string). Entries created when
    // mesh-dial sees a new roster member with no session; cleared once
    // start_call_to_pub is re-dispatched (or the username_lookup /
    // key_fetch returns NOT_FOUND and we give up).
    std::map<std::string, PendingMeshDial> pending_mesh_dials;
    // Reverse mapping: an in-flight username (sent via key_fetch as part
    // of mesh-bootstrap) → the peer_pub string we're trying to dial.
    // kKeyFetchResp consults this on success to know whether to retry
    // a mesh-dial after standing up the session.
    std::map<std::string, std::string> mesh_bootstrap_pending;

    // Single self-mute flag applied to every active call. Newly-created
    // MediaCalls inherit it via the same set_self_muted hook.
    bool self_muted = false;
};

ChatClient::ChatClient(QObject* parent) : QObject(parent), impl_(std::make_unique<Impl>()) {}

ChatClient::~ChatClient() { disconnect(); }

void ChatClient::connect(const QString& host, std::uint16_t port, const QString& user,
                         const std::array<std::uint8_t, 32>& seed) {
    connect_tls(host, port, user, seed,
                /*use_tls=*/false, /*ca_file=*/QString(),
                /*insecure_skip_verify=*/false, /*sni_hostname=*/QString());
}

void ChatClient::connect_tls(const QString& host, std::uint16_t port,
                              const QString& user,
                              const std::array<std::uint8_t, 32>& seed,
                              bool use_tls,
                              const QString& ca_file,
                              bool insecure_skip_verify,
                              const QString& sni_hostname) {
    if (impl_->running.exchange(true)) return;
    impl_->host = host;
    impl_->port = port;
    impl_->username = user;
    impl_->seed = seed;
    impl_->use_tls = use_tls;
    impl_->tls_ca_file = ca_file.toStdString();
    impl_->tls_insecure_skip_verify = insecure_skip_verify;
    impl_->tls_sni = sni_hostname.toStdString();
    impl_->worker = std::thread([this]() {
        try {
            if (sodium_init() < 0) {
                emit errorOccurred(QString("sodium init failed"));
                return;
            }
            // Identity comes from the seed handed in by LoginDialog (which
            // unlocked it from the on-disk passphrase-protected vault). The
            // <username>.db SQLite store keeps message / channel state but
            // is no longer the source of truth for identity material.
            const QString data_root =
                QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
            QDir().mkpath(data_root);
            impl_->store_path =
                (data_root + "/" + impl_->username + ".db").toStdString();
            // Derive a 32-byte at-rest encryption key from the vault seed
            // via HKDF before the store opens — sensitive columns
            // (inbox/outbox plaintext) are AEAD-wrapped per row using
            // sub-keys of this master. First-time opens migrate any
            // legacy plaintext rows in a single transaction; bumps
            // PRAGMA user_version 0→2.
            std::array<std::uint8_t, 32> store_master_key{};
            {
                static constexpr std::string_view kInfo = "FinBit-DB-Master-v1";
                auto prk = fb::crypto::hkdf_extract(
                    std::span<const std::uint8_t>(),
                    std::span<const std::uint8_t>(impl_->seed.data(),
                                                   impl_->seed.size()));
                auto vec = fb::crypto::hkdf_expand(prk,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(kInfo.data()),
                        kInfo.size()),
                    32);
                std::memcpy(store_master_key.data(), vec.data(), 32);
                sodium_memzero(vec.data(), vec.size());
            }
            impl_->store = fb::store::SqliteStore::open(
                impl_->store_path,
                std::span<const std::uint8_t>(store_master_key.data(), 32));
            sodium_memzero(store_master_key.data(), store_master_key.size());

            impl_->identity = fb::crypto::Identity::from_seed(impl_->seed);
            // We intentionally no longer call save_identity() — it was a
            // legacy path that wrote the secret key into the SQLite store
            // in cleartext. Now that LoginDialog + identity_vault are the
            // source of truth, that on-disk copy was redundant *and* the
            // single biggest at-rest secret leak (see
            // docs/security-audit.md). Wipe the in-memory raw seed once
            // Identity::from_seed has copied it into mlock'd memory.
            sodium_memzero(impl_->seed.data(), impl_->seed.size());
            emit log(QString("identity unlocked from vault, store=%1")
                         .arg(QString::fromStdString(impl_->store_path)));
            impl_->x25519 = derive_x25519(*impl_->identity);

            emit connected(QString::fromStdString(impl_->identity->fingerprint()));

            // ---- Serverless overlay setup ----
            // Lifetime: tied to the worker thread; both objects use
            // the worker's Conn for outbound, and inbound dispatch
            // happens in the EPOLLIN loop where Frame.peer arrives.
            //
            // SendCallbacks build a Frame.peer envelope and write it
            // straight onto the connection. Recipient routing is by
            // PeerInfo.pubkey — the central server forwards based on
            // the recipient_pubkey field. Empty pubkey = broadcast,
            // which gossip uses for flood pulls.
            impl_->username_log =
                std::make_unique<fb::identity::UsernameLog>(*impl_->store);
            auto wrap_peer_send =
                [this](fb::proto::PeerEnvelope::Kind kind,
                        const fb::p2p::PeerInfo& peer,
                        std::span<const std::uint8_t> payload) {
                    fb::proto::Frame f;
                    auto* env = f.mutable_peer();
                    env->set_kind(kind);
                    // Stamp our own sender_pubkey on direct-P2P
                    // sends — the central server stamps it on
                    // server-relayed sends, but a direct peer has
                    // no such authority and the receiver needs it
                    // for routing.
                    env->set_sender_pubkey(std::string(
                        reinterpret_cast<const char*>(
                            impl_->identity->public_key().data()),
                        impl_->identity->public_key().size()));
                    if (peer.pubkey.size() == 32) {
                        env->set_recipient_pubkey(std::string(
                            peer.pubkey.begin(), peer.pubkey.end()));
                    }
                    env->set_payload(std::string(payload.begin(),
                                                  payload.end()));
                    auto wire = serialize(f);
                    // Prefer PeerNet for peers with a dialable
                    // wss:// addr — that's the direct path. Falls
                    // back to the central-server relay when the
                    // peer is unreachable directly OR when no
                    // PeerNet is configured.
                    bool sent_direct = false;
                    if (impl_->peer_net &&
                        peer.addr.rfind("wss://", 0) == 0) {
                        sent_direct = impl_->peer_net->send(peer,
                            std::span<const std::uint8_t>(
                                wire.data(), wire.size()));
                    }
                    if (!sent_direct) {
                        try {
                            blocking_send(impl_->conn, wire);
                        } catch (const std::exception& e) {
                            emit log(QString("overlay send failed: %1")
                                         .arg(e.what()));
                        }
                    }
                };
            impl_->username_gossip =
                std::make_unique<fb::identity::UsernameGossip>(
                    *impl_->username_log,
                    [wrap_peer_send](const fb::p2p::PeerInfo& peer,
                                      std::span<const std::uint8_t> wire) {
                        wrap_peer_send(fb::proto::PeerEnvelope::GOSSIP,
                                        peer, wire);
                    });
            // Self-NodeId for the DHT routing table.
            auto self_nid = fb::p2p::node_id_from_pubkey(
                std::span<const std::uint8_t>(
                    impl_->identity->public_key().data(),
                    impl_->identity->public_key().size()));
            impl_->dht = std::make_unique<fb::p2p::DhtNode>(
                self_nid,
                [wrap_peer_send](const fb::p2p::PeerInfo& peer,
                                  std::span<const std::uint8_t> wire) {
                    wrap_peer_send(fb::proto::PeerEnvelope::DHT,
                                    peer, wire);
                });

            // ---- DM-text decrypt helper (I1) ----
            // Focused refactor of the existing inline kEnvelope DM
            // path. Reused by both Frame.envelope (server-relay) and
            // PeerEnvelope::DM (direct-P2P) so the user-visible
            // "alice DMs bob" works identically over both transports.
            //
            // Scope: TEXT payloads only. Other DmPayload kinds
            // (channel_key, mls_*, media_signal) still flow through
            // the existing inline kEnvelope handler — those have
            // deeper integration with channel state / MLS pending
            // joins / media call queues that would balloon this
            // helper. A follow-up can hoist them in too.
            //
            // Returns true if the envelope decrypted to a TEXT
            // payload AND messageReceived was emitted; false on any
            // failure (bad crypto, non-text payload, malformed AAD).
            // Caller can fall through to the inline kEnvelope handler
            // on false to preserve the legacy code path for non-text
            // payloads.
            auto try_decrypt_dm_text =
                [this](const fb::proto::Envelope& env) -> bool {
                if (env.sender_pubkey().size() != 32) return false;
                const std::string sender_pub_bytes(
                    env.sender_pubkey().begin(),
                    env.sender_pubkey().end());

                // Locate (or create) the ratchet session for this
                // peer. Same logic as the inline kEnvelope handler:
                // reuse an existing session if one exists for this
                // pubkey; otherwise spin up a fresh init_bob.
                std::array<std::uint8_t, 32> sender_pub_arr{};
                std::memcpy(sender_pub_arr.data(),
                             sender_pub_bytes.data(), 32);
                std::string sname;
                for (auto& [name, s] : impl_->sessions) {
                    if (s.rat && s.peer_pub == sender_pub_arr) {
                        sname = name;
                        break;
                    }
                }
                if (sname.empty()) {
                    sname = "peer:" + sender_pub_bytes.substr(0, 8);
                }
                auto& sess = impl_->sessions[sname];
                if (!sess.rat) {
                    std::array<std::uint8_t, 32> peer_x{};
                    if (crypto_sign_ed25519_pk_to_curve25519(
                            peer_x.data(),
                            reinterpret_cast<const std::uint8_t*>(
                                sender_pub_bytes.data())) != 0) {
                        return false;
                    }
                    auto shared = derive_shared_secret(
                        impl_->x25519,
                        std::span<const std::uint8_t, 32>(
                            peer_x.data(), 32));
                    sess.rat.emplace(
                        fb::crypto::DoubleRatchet::init_bob(
                            std::span<const std::uint8_t, 32>(
                                shared.data(), shared.size()),
                            std::span<const std::uint8_t, 32>(
                                impl_->x25519.priv.data(), 32),
                            std::span<const std::uint8_t, 32>(
                                impl_->x25519.pub.data(), 32)));
                    sess.peer_pub = sender_pub_arr;
                    sess.peer_x   = peer_x;
                }

                // Re-derive + cross-check Envelope.aad just like the
                // existing inline path.
                std::vector<std::uint8_t> outer_aad(
                    env.aad().begin(), env.aad().end());
                if (!outer_aad.empty()) {
                    std::vector<std::uint8_t> envid(
                        env.envelope_id().begin(),
                        env.envelope_id().end());
                    auto expected = envelope_aad_bytes(
                        std::span<const std::uint8_t>(envid.data(),
                                                       envid.size()),
                        env.timestamp_ms());
                    if (expected != outer_aad) return false;
                }

                // Decrypt via the ratchet.
                std::vector<std::uint8_t> ct(env.ciphertext().begin(),
                                              env.ciphertext().end());
                std::optional<std::vector<std::uint8_t>> pt;
                try {
                    pt = sess.rat->decrypt(
                        std::span<const std::uint8_t>(ct.data(), ct.size()),
                        std::span<const std::uint8_t>(outer_aad.data(),
                                                       outer_aad.size()));
                } catch (...) { return false; }
                if (!pt) return false;

                // Parse the inner DmPayload. Only TEXT goes through
                // this helper — everything else returns false so the
                // caller can let the inline kEnvelope handler take
                // over.
                fb::proto::DmPayload payload;
                if (!payload.ParseFromArray(
                        pt->data(), static_cast<int>(pt->size()))) {
                    return false;
                }
                if (payload.body_case() != fb::proto::DmPayload::kText) {
                    return false;
                }

                // Fingerprint = peer's stable display ID; cached
                // username if we know it (same lookup the inline
                // path does).
                const auto peer_fp = QString::fromStdString(
                    fb::crypto::Identity::fingerprint(sender_pub_arr));
                QString cached_username;
                if (impl_->store) {
                    if (auto u = impl_->store->peer_name(
                            std::span<const std::uint8_t>(
                                sender_pub_arr.data(),
                                sender_pub_arr.size()))) {
                        cached_username = QString::fromStdString(*u);
                    }
                }
                emit messageReceived(peer_fp, cached_username,
                    QString::fromStdString(payload.text()));
                return true;
            };
            (void)try_decrypt_dm_text;   // referenced from PeerEnvelope dispatch
            // ---- PeerNet (direct peer-to-peer) ----
            // Optional. Configured via env vars so the desktop UI
            // doesn't need an "expose my port" toggle yet:
            //   FB_PEER_LISTEN_PORT   uint16, e.g. 4443
            //   FB_PEER_LISTEN_CERT   PEM cert path
            //   FB_PEER_LISTEN_KEY    PEM key  path
            //   FB_PEER_LISTEN_HOST   bind host (default 0.0.0.0)
            //   FB_PEER_DIALER_CA     PEM CA   path (empty = system)
            //   FB_PEER_DIALER_INSECURE  any non-empty value = skip
            //                            cert verification on dial
            //   FB_PEER_PUBLIC_ADDR   public reachability for our
            //                         self-published provider record
            //                         (e.g. "wss://my.host:4443").
            //                         If empty, no record is
            //                         published — peer-discovery
            //                         still works for OTHERS to
            //                         find us if they get our addr
            //                         out-of-band (bootstrap file).
            auto env = [](const char* k) -> std::string {
                const char* v = std::getenv(k);
                return v ? v : std::string();
            };
            const std::string peer_port_str = env("FB_PEER_LISTEN_PORT");
            const std::string peer_cert     = env("FB_PEER_LISTEN_CERT");
            const std::string peer_key      = env("FB_PEER_LISTEN_KEY");
            const std::string peer_host     = env("FB_PEER_LISTEN_HOST");
            const std::string dialer_ca     = env("FB_PEER_DIALER_CA");
            const bool dialer_insecure      = !env("FB_PEER_DIALER_INSECURE").empty();
            impl_->own_p2p_addr             = env("FB_PEER_PUBLIC_ADDR");

            // I4: parse FB_OFFLINE_RELAYS as a comma-separated list
            // of hex pubkeys (64 hex chars each). Each declared
            // relay gets embedded in our own ProviderRecord on
            // every republish so senders can find them when we're
            // offline. Quietly skip malformed entries — bad CSV
            // shouldn't break startup.
            {
                const std::string csv = env("FB_OFFLINE_RELAYS");
                std::size_t pos = 0;
                while (pos < csv.size()) {
                    auto end = csv.find(',', pos);
                    if (end == std::string::npos) end = csv.size();
                    auto chunk = csv.substr(pos, end - pos);
                    pos = end + 1;
                    // Trim whitespace.
                    while (!chunk.empty() && std::isspace(
                            static_cast<unsigned char>(chunk.front()))) {
                        chunk.erase(0, 1);
                    }
                    while (!chunk.empty() && std::isspace(
                            static_cast<unsigned char>(chunk.back()))) {
                        chunk.pop_back();
                    }
                    if (chunk.size() != 64) continue;
                    std::vector<std::uint8_t> pub(32);
                    bool ok = true;
                    auto nyb = [](char c, int& v) {
                        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
                        if (c >= 'a' && c <= 'f') { v = 10 + c - 'a'; return true; }
                        if (c >= 'A' && c <= 'F') { v = 10 + c - 'A'; return true; }
                        return false;
                    };
                    for (std::size_t i = 0; i < 32 && ok; ++i) {
                        int hi = 0, lo = 0;
                        ok = nyb(chunk[i*2], hi) && nyb(chunk[i*2+1], lo);
                        if (ok) pub[i] = static_cast<std::uint8_t>((hi<<4)|lo);
                    }
                    if (ok) impl_->own_offline_relays.push_back(std::move(pub));
                }
                if (!impl_->own_offline_relays.empty()) {
                    emit log(QString("offline relays designated: %1")
                                 .arg(static_cast<qulonglong>(
                                     impl_->own_offline_relays.size())));
                }
            }
            // I4: We also act as a relay for any peer who designated
            // us. Always allocate the store; deposit handlers
            // populate it on demand.
            impl_->offline_store =
                std::make_unique<fb::p2p::OfflineRelayStore>();

            // I3: optional gossipsub (P2PNode) for serverless
            // channel fan-out. Configured via env:
            //   FB_GOSSIP_PORT    uint16, our gossipsub listen port
            //   FB_GOSSIP_DIAL    "host:port[,host:port,...]" of
            //                     bootstrap gossip peers
            // When the port is set, we instantiate P2PNode bound
            // to that port and subscribe to every existing channel
            // topic as soon as we know the channel id. Inbound
            // topic messages route through try_decrypt_dm_text
            // (channel envelopes are also wire-form Envelope; the
            // helper handles the same crypto path).
            const std::string gport_str = env("FB_GOSSIP_PORT");
            if (!gport_str.empty()) {
                const auto gport = static_cast<std::uint16_t>(
                    std::atoi(gport_str.c_str()));
                impl_->gossip = std::make_unique<fb::p2p::P2PNode>(
                    "0.0.0.0", gport,
                    std::span<const std::uint8_t>(
                        impl_->identity->public_key().data(),
                        impl_->identity->public_key().size()));
                impl_->gossip->set_on_topic_message(
                    [this](const std::string& topic,
                            std::span<const std::uint8_t> payload,
                            const fb::p2p::PeerInfo& origin) {
                        // Channel topics are "fb-chan:<hex>"; payload
                        // is a serialized Envelope. We surface the
                        // arrival via the activity log; full
                        // channel-decrypt routing into ChannelState
                        // is the same refactor pending for direct-DM
                        // dispatch — both share the kEnvelope inline
                        // body that hasn't been hoisted yet.
                        emit log(QString("channel gossip: topic=%1 "
                                          "%2B from %3-byte peer")
                                     .arg(QString::fromStdString(topic))
                                     .arg(static_cast<qulonglong>(
                                         payload.size()))
                                     .arg(static_cast<qulonglong>(
                                         origin.pubkey.size())));
                    });
                impl_->gossip->start();
                emit log(QString("gossip P2PNode started on :%1")
                             .arg(gport));
                // Bootstrap: dial out to FB_GOSSIP_DIAL peers (CSV).
                const std::string dials = env("FB_GOSSIP_DIAL");
                std::size_t pos = 0;
                while (pos < dials.size()) {
                    auto end = dials.find(',', pos);
                    if (end == std::string::npos) end = dials.size();
                    auto pair = dials.substr(pos, end - pos);
                    pos = end + 1;
                    auto colon = pair.find(':');
                    if (colon == std::string::npos) continue;
                    impl_->gossip->dial(
                        pair.substr(0, colon),
                        static_cast<std::uint16_t>(
                            std::atoi(pair.c_str() + colon + 1)));
                }
            }
            const bool any_peer_env =
                !peer_port_str.empty() || !peer_cert.empty() ||
                !peer_key.empty() || !dialer_ca.empty() ||
                dialer_insecure;
            if (any_peer_env) {
                impl_->peer_net = std::make_unique<fb::p2p::PeerNet>();
                fb::p2p::PeerDialerOptions dopts;
                dopts.ca_file              = dialer_ca;
                dopts.insecure_skip_verify = dialer_insecure;
                impl_->peer_net->set_dialer(dopts);
                // Inbound: stash on the overlay queue so the worker
                // thread (this same thread, in its main poll loop)
                // drains and dispatches into DhtNode /
                // UsernameGossip sequentially.
                impl_->peer_net->set_on_message(
                    [this](const fb::p2p::PeerInfo& from,
                            std::span<const std::uint8_t> bytes) {
                        Impl::OverlayInboundMsg m;
                        m.sender_pubkey = from.pubkey;
                        m.bytes.assign(bytes.begin(), bytes.end());
                        std::lock_guard lk(impl_->overlay_inbox_mu);
                        impl_->overlay_inbox.push_back(std::move(m));
                    });
                if (!peer_port_str.empty() && !peer_cert.empty() &&
                    !peer_key.empty()) {
                    fb::p2p::PeerListenerOptions lopts;
                    lopts.bind_host =
                        peer_host.empty() ? "0.0.0.0" : peer_host;
                    lopts.bind_port = static_cast<std::uint16_t>(
                        std::atoi(peer_port_str.c_str()));
                    lopts.tls_cert_pem = peer_cert;
                    lopts.tls_key_pem  = peer_key;
                    try {
                        impl_->peer_net->start_listener(lopts);
                        emit log(QString("PeerNet listening on "
                                          "%1:%2")
                                     .arg(QString::fromStdString(
                                         lopts.bind_host))
                                     .arg(impl_->peer_net->listener_port()));
                    } catch (const std::exception& e) {
                        emit log(QString("PeerNet listener failed: %1")
                                     .arg(e.what()));
                    }
                } else {
                    emit log(QString("PeerNet enabled in dialer-only "
                                      "mode (no listener)"));
                }
            }

            // Seed the DHT routing table from the bootstrap file
            // (FB_BOOTSTRAP_FILE / XDG_CONFIG / $HOME/.finbit).
            // Without this, the routing table starts empty and
            // publish() / lookup() can't reach anyone until the
            // first inbound PeerEnvelope teaches us about a peer.
            try {
                auto bs = fb::p2p::load_default_bootstrap();
                for (const auto& p : bs.peers) {
                    impl_->dht->routing().observe(p);
                }
                if (!bs.peers.empty()) {
                    emit log(QString("loaded %1 bootstrap peer(s) "
                                      "(malformed lines: %2)")
                                 .arg(static_cast<qulonglong>(bs.peers.size()))
                                 .arg(static_cast<qulonglong>(
                                     bs.malformed_lines)));
                }
            } catch (...) {
                // load_default_bootstrap doesn't throw, but defend
                // against a future change. Empty bootstrap is fine —
                // peers still get learned from inbound traffic.
            }

            // Transport selection. impl_->use_tls is set by
            // connect_tls; the legacy connect() forwards with
            // use_tls=false so existing call sites keep their plain
            // TCP behaviour.
            if (impl_->use_tls) {
                impl_->tls.emplace();
                fb::net::TlsClientOptions tlsopts;
                tlsopts.ca_file              = impl_->tls_ca_file;
                tlsopts.insecure_skip_verify = impl_->tls_insecure_skip_verify;
                tlsopts.sni_hostname         = impl_->tls_sni;
                if (impl_->tls_insecure_skip_verify) {
                    emit log(QString(
                        "WARNING: TLS cert validation disabled "
                        "(--tls-insecure-skip-verify). Use only "
                        "against a known self-signed dev server."));
                }
                impl_->tls->connect(impl_->host.toStdString(),
                                     impl_->port, tlsopts);
                impl_->conn.tls = &impl_->tls.value();
            } else {
                impl_->sock.emplace(
                    fb::net::tcp_connect(impl_->host.toStdString(),
                                          impl_->port));
                impl_->conn.sock = &impl_->sock.value();
            }

            // ClientHello
            {
                fb::proto::Frame f;
                auto* hello = f.mutable_hello();
                hello->set_identity_pubkey(std::string(
                    reinterpret_cast<const char*>(impl_->identity->public_key().data()),
                    impl_->identity->public_key().size()));
                hello->set_username(impl_->username.toStdString());
                hello->set_protocol_version(fb::config::kProtocolVersion);
                blocking_send(impl_->conn, serialize(f));
            }

            // Wait for ServerHello + sign the challenge it carries.
            {
                fb::net::FrameDecoder hello_dec;
                std::array<std::uint8_t, 4096> hbuf;
                std::vector<std::uint8_t> hello_frame;
                const auto hello_deadline =
                    std::chrono::steady_clock::now() + std::chrono::seconds(3);
                while (std::chrono::steady_clock::now() < hello_deadline) {
                    auto n = conn_read_with_timeout(impl_->conn,
                        std::span<std::uint8_t>(hbuf.data(), hbuf.size()),
                        100);
                    if (n == 0) continue;
                    impl_->dec.feed(std::span<const std::uint8_t>(
                        hbuf.data(), n));
                    if (impl_->dec.try_pop(hello_frame) ==
                        fb::net::FrameDecoder::Status::kFrameReady) {
                        break;
                    }
                }
                if (hello_frame.empty()) {
                    emit errorOccurred("no ServerHello");
                    return;
                }
                fb::proto::Frame sh;
                if (!sh.ParseFromArray(hello_frame.data(),
                                       static_cast<int>(hello_frame.size())) ||
                    sh.body_case() != fb::proto::Frame::kServerHello ||
                    !sh.server_hello().accepted() ||
                    sh.server_hello().server_random().size() != 32) {
                    emit errorOccurred("ServerHello rejected or malformed");
                    return;
                }
                std::vector<std::uint8_t> ch(sh.server_hello().server_random().begin(),
                                             sh.server_hello().server_random().end());
                auto sig = impl_->identity->sign(
                    std::span<const std::uint8_t>(ch.data(), ch.size()));
                fb::proto::Frame ackf;
                ackf.mutable_hello_ack()->set_signature(
                    std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));
                blocking_send(impl_->conn, serialize(ackf));
            }

            // Upload prekey bundle
            {
                fb::proto::Frame f;
                auto* up = f.mutable_key_upload();
                auto* b = up->mutable_bundle();
                b->set_identity_pubkey(std::string(
                    reinterpret_cast<const char*>(impl_->identity->public_key().data()),
                    impl_->identity->public_key().size()));
                b->set_signed_prekey(std::string(
                    reinterpret_cast<const char*>(impl_->x25519.pub.data()),
                    impl_->x25519.pub.size()));
                b->set_published_at_ms(static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count()));
                blocking_send(impl_->conn, serialize(f));
            }

            emit log(QString("connected to %1:%2 as %3")
                         .arg(impl_->host)
                         .arg(impl_->port)
                         .arg(impl_->username));

            // Helpers (capture impl_) for persisting channel state.
            auto persist_chan_meta = [this](const std::string& name, const ChannelState& cs) {
                if (!impl_->store) return;
                impl_->store->chan_save(
                    name,
                    std::span<const std::uint8_t>(cs.id.data(), cs.id.size()),
                    std::span<const std::uint8_t>(cs.own_dist.data(), cs.own_dist.size()),
                    cs.crypto);
            };
            auto persist_chan_session = [this](const std::string& name, const ChannelState& cs) {
                if (!impl_->store) return;
                auto blob = cs.session->serialize_state();
                auto key = std::string("__chanstate__:") + name;
                impl_->store->save_session(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(key.data()), key.size()),
                    std::span<const std::uint8_t>(blob.data(), blob.size()));
            };
            auto persist_chan_peer_dist = [this](const ChannelState& cs,
                                                  std::span<const std::uint8_t> peer_pub,
                                                  std::span<const std::uint8_t> peer_dist) {
                if (!impl_->store) return;
                impl_->store->chan_save_peer(
                    std::span<const std::uint8_t>(cs.id.data(), cs.id.size()),
                    peer_pub, peer_dist);
            };
            // MLS persistence: write the bootstrap seed for a kMls
            // channel. Idempotent on the store side (UPSERT). Called
            // exactly once per channel — at create() for the inviter,
            // at Welcome.complete() for the joiner.
            auto persist_mls_seed = [this](ChannelState& cs) {
                if (!impl_->store || !cs.mls) return;
                auto seed_blob = cs.mls->serialize_seed();
                impl_->store->mls_group_save(
                    std::span<const std::uint8_t>(cs.id.data(), cs.id.size()),
                    std::span<const std::uint8_t>(seed_blob.data(),
                                                   seed_blob.size()));
                cs.mls_next_seq = 0;
            };
            // MLS persistence: append the most recent op produced by
            // the live MlsGroup to the on-disk log. Each MlsGroup
            // mutator (add_member / propose_add_member / commit_pending
            // / handle_proposal / apply_commit) appends exactly one
            // entry to operation_log(); this helper serializes that
            // entry under the next sequence number.
            //
            // Call EXACTLY once per mutator call. If the call throws
            // before this helper runs, no on-disk op is persisted —
            // mlspp's State remains unchanged in that case (mutators
            // only commit changes when they return without throwing),
            // so the log stays consistent with the live state.
            auto persist_mls_last_op = [this](ChannelState& cs) {
                if (!impl_->store || !cs.mls) return;
                auto ops = cs.mls->operation_log();
                if (ops.empty()) return;
                const auto& last = ops.back();
                impl_->store->mls_group_op_append(
                    std::span<const std::uint8_t>(cs.id.data(), cs.id.size()),
                    cs.mls_next_seq,
                    std::span<const std::uint8_t>(last.data(), last.size()));
                cs.mls_next_seq++;
            };

            // Restore persisted channels from the local store: reload the
            // GroupSession state, install peer distributions, subscribe.
            // Channels survive a restart — reading inbound messages and
            // continuing to send all work without losing chain state.
            for (const auto& row : impl_->store->chan_list()) {
                if (row.channel_id.size() != 32) continue;
                ChannelState cs;
                std::memcpy(cs.id.data(), row.channel_id.data(), 32);
                cs.own_dist = row.own_dist;
                cs.crypto = row.crypto;
                // MLS restore via the operation-replay layer:
                // load the bootstrap seed + every saved op for this
                // channel, hand both to MlsGroup::from_seed_and_log,
                // and the rebuilt State is byte-equivalent to the
                // pre-shutdown one. cs.mls_next_seq is set to the
                // next free sequence number so future appends don't
                // collide.
                //
                // If the channel is kMls but the store has no row
                // for it (legacy DB created before persistence
                // shipped, or the seed save was lost mid-write),
                // fall through with cs.mls null. The receive path
                // tolerates this — SenderKeys decrypt returns
                // nullopt for MLS ciphertexts so the channel stays
                // alive but messages from that epoch can't be read
                // until a re-invite re-establishes the group.
                if (cs.crypto ==
                    fb::store::SqliteStore::ChannelCrypto::kMls) {
                    auto snap = impl_->store->mls_group_load(
                        std::span<const std::uint8_t>(
                            row.channel_id.data(), row.channel_id.size()));
                    if (snap) {
                        try {
                            cs.mls = fb::crypto::MlsGroup::from_seed_and_log(
                                std::span<const std::uint8_t>(
                                    snap->seed.data(), snap->seed.size()),
                                snap->ops);
                            cs.mls_next_seq = snap->next_seq;
                            // Membership cache: prime so the first
                            // post-restart add fans out to existing
                            // members instead of treating them as
                            // new strangers.
                            const auto& my_pub =
                                impl_->identity->public_key();
                            for (const auto& id :
                                 cs.mls->member_identities()) {
                                if (id.size() != 32) continue;
                                if (std::equal(my_pub.begin(),
                                                my_pub.end(),
                                                id.begin())) continue;
                                cs.mls_member_pubs.insert(
                                    std::string(id.begin(), id.end()));
                            }
                            emit log(QString("MLS channel #%1 restored "
                                              "(member_count=%2, "
                                              "ops_replayed=%3)")
                                         .arg(QString::fromStdString(row.name))
                                         .arg(cs.mls->member_count())
                                         .arg(static_cast<qulonglong>(snap->ops.size())));
                        } catch (const std::exception& e) {
                            emit errorOccurred(QString(
                                "MLS restore for #%1 failed: %2 — "
                                "re-invite members to re-establish")
                                .arg(QString::fromStdString(row.name))
                                .arg(e.what()));
                        }
                    } else {
                        emit log(QString("MLS channel #%1 has no on-disk "
                                          "seed (legacy or partial save) "
                                          "— re-invite members to "
                                          "re-establish")
                                     .arg(QString::fromStdString(row.name)));
                    }
                }

                // Try the full-state blob first; if absent, fall back to a
                // fresh GroupSession + per-peer distribution install (sender
                // chain state is then absent — first send creates a new chain).
                auto state_key = std::string("__chanstate__:") + row.name;
                auto state_blob = impl_->store->load_session(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(state_key.data()),
                        state_key.size()));
                if (state_blob) {
                    auto restored = fb::crypto::GroupSession::deserialize_state(
                        std::span<const std::uint8_t>(state_blob->data(),
                                                       state_blob->size()));
                    if (restored) cs.session = std::move(restored);
                }
                // Install any persisted peer distributions on top (idempotent).
                for (const auto& peer_row : impl_->store->chan_peers(
                         std::span<const std::uint8_t>(row.channel_id.data(),
                                                        row.channel_id.size()))) {
                    try {
                        cs.session->install_peer_distribution(
                            std::span<const std::uint8_t>(peer_row.peer_pub.data(),
                                                           peer_row.peer_pub.size()),
                            std::span<const std::uint8_t>(peer_row.peer_dist.data(),
                                                           peer_row.peer_dist.size()));
                    } catch (...) {}
                }

                // Subscribe so the server fans out future channel envelopes.
                fb::proto::Frame subf;
                subf.mutable_chan_subscribe()->set_channel_group_id(
                    std::string(row.channel_id.begin(), row.channel_id.end()));
                blocking_send(impl_->conn, serialize(subf));
                cs.subscribed = true;

                impl_->chan_id_to_name[std::string(
                    reinterpret_cast<const char*>(cs.id.data()), cs.id.size())] = row.name;
                impl_->channels.emplace(row.name, std::move(cs));
                emit channelJoined(QString::fromStdString(row.name));
                emit log(QString("restored channel #%1").arg(QString::fromStdString(row.name)));
            }

            // Periodic overlay maintenance helpers (P3).
            //   * republish: rotate our own provider record before
            //     its TTL expires. Default cadence = half the TTL.
            //   * gossip pull: ask each known routing-table peer
            //     for "every claim newer than our last sync with
            //     them" so the username log converges across the
            //     swarm.
            constexpr std::uint64_t kRepublishIntervalMs =
                30 * 60 * 1000;   // 30 min (TTL is 1h by default)
            constexpr std::uint64_t kGossipPullIntervalMs =
                5 * 60 * 1000;    // 5 min per peer
            auto now_ms = []() {
                return static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now()
                            .time_since_epoch()).count());
            };
            auto republish_self = [&]() {
                if (!impl_->dht || impl_->own_p2p_addr.empty()) return;
                try {
                    auto sig_pub = std::span<const std::uint8_t>(
                        impl_->identity->public_key().data(),
                        impl_->identity->public_key().size());
                    auto sig_priv = std::span<const std::uint8_t>(
                        impl_->identity->secret_key().data(),
                        impl_->identity->secret_key().size());
                    auto rec = fb::p2p::build_record(
                        sig_pub, sig_priv,
                        std::vector<std::string>{impl_->own_p2p_addr},
                        now_ms(),
                        fb::p2p::kDefaultProviderTtlMs,
                        impl_->own_offline_relays);
                    auto sent = impl_->dht->publish(rec);
                    emit log(QString("DHT republish: addr=%1 sent_to=%2 "
                                      "relays=%3")
                                 .arg(QString::fromStdString(
                                     impl_->own_p2p_addr))
                                 .arg(static_cast<qulonglong>(sent))
                                 .arg(static_cast<qulonglong>(
                                     impl_->own_offline_relays.size())));
                } catch (const std::exception& e) {
                    emit log(QString("DHT republish failed: %1")
                                 .arg(e.what()));
                }
            };
            auto gossip_pull_round = [&]() {
                if (!impl_->username_gossip || !impl_->dht) return;
                const auto peers = impl_->dht->routing().all();
                std::size_t pulled = 0;
                for (const auto& p : peers) {
                    if (p.pubkey.size() != 32) continue;
                    const std::string key(p.pubkey.begin(),
                                            p.pubkey.end());
                    auto it = impl_->gossip_watermark.find(key);
                    const std::uint64_t since =
                        (it != impl_->gossip_watermark.end()) ? it->second : 0;
                    impl_->username_gossip->sync_with(p, since);
                    impl_->gossip_watermark[key] = now_ms();
                    ++pulled;
                }
                if (pulled > 0) {
                    emit log(QString("gossip pull: %1 peer(s)")
                                 .arg(static_cast<qulonglong>(pulled)));
                }
            };

            // Main I/O loop.
            std::vector<std::uint8_t> rxbuf(4096);
            while (impl_->running) {
                // 0a. Drain inbound overlay messages from PeerNet
                //     workers (direct-P2P traffic). Same dispatch
                //     path as server-relayed Frame.peer below.
                std::deque<Impl::OverlayInboundMsg> overlay_drain;
                {
                    std::lock_guard lk(impl_->overlay_inbox_mu);
                    overlay_drain.swap(impl_->overlay_inbox);
                }
                for (auto& m : overlay_drain) {
                    fb::proto::Frame f;
                    if (!f.ParseFromArray(m.bytes.data(),
                                           static_cast<int>(m.bytes.size()))) {
                        continue;
                    }
                    if (f.body_case() != fb::proto::Frame::kPeer) continue;
                    const auto& pe = f.peer();
                    fb::p2p::PeerInfo from{};
                    if (pe.sender_pubkey().size() == 32) {
                        from.id = fb::p2p::node_id_from_pubkey(
                            std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t*>(
                                    pe.sender_pubkey().data()),
                                32));
                        from.pubkey.assign(pe.sender_pubkey().begin(),
                                            pe.sender_pubkey().end());
                        if (impl_->dht) impl_->dht->observe(from);
                    }
                    auto payload = std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(
                            pe.payload().data()),
                        pe.payload().size());
                    switch (pe.kind()) {
                        case fb::proto::PeerEnvelope::DHT:
                            if (impl_->dht) impl_->dht->on_message(from, payload);
                            break;
                        case fb::proto::PeerEnvelope::GOSSIP:
                            if (impl_->username_gossip)
                                impl_->username_gossip->on_message(from, payload);
                            break;
                        case fb::proto::PeerEnvelope::DM: {
                            // Direct-P2P DM via PeerNet: payload is
                            // a wire-form Envelope. Decrypt + emit
                            // via try_decrypt_dm_text (TEXT path
                            // only; other DmPayload kinds still
                            // route through the inline kEnvelope
                            // handler on the server-relay path).
                            fb::proto::Envelope inner;
                            if (!inner.ParseFromArray(
                                    payload.data(),
                                    static_cast<int>(payload.size()))) {
                                break;
                            }
                            if (try_decrypt_dm_text(inner)) {
                                emit log("DM (PeerNet) decrypted via "
                                          "I1 helper");
                            } else {
                                emit log("DM (PeerNet) received but "
                                          "decrypt failed or non-text "
                                          "payload");
                            }
                            break;
                        }
                        case fb::proto::PeerEnvelope::OFFLINE_DEPOSIT: {
                            // Someone designated us as a relay for
                            // pe.recipient_pubkey and is depositing
                            // an encrypted blob. Store opaquely —
                            // we can't decrypt (it's encrypted to
                            // the recipient).
                            if (!impl_->offline_store) break;
                            const auto& rec = pe.recipient_pubkey();
                            if (rec.size() != 32) break;
                            auto r = impl_->offline_store->deposit(
                                std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t*>(
                                        rec.data()), 32),
                                payload);
                            emit log(QString("OFFLINE_DEPOSIT: %1")
                                .arg(r == fb::p2p::OfflineRelayStore::DepositResult::kAccepted
                                     ? "accepted"
                                     : "rejected"));
                            break;
                        }
                        case fb::proto::PeerEnvelope::OFFLINE_FETCH: {
                            // Recipient is asking for everything
                            // we've held for them. The sender's
                            // pubkey IS the recipient pubkey here
                            // (you can only fetch your own queue).
                            if (!impl_->offline_store) break;
                            if (from.pubkey.size() != 32) break;
                            auto blobs = impl_->offline_store
                                ->fetch_and_clear(
                                    std::span<const std::uint8_t>(
                                        from.pubkey.data(),
                                        from.pubkey.size()));
                            if (!blobs.empty()) {
                                emit log(QString("OFFLINE_FETCH: "
                                    "delivering %1 queued blob(s) "
                                    "to peer")
                                    .arg(static_cast<qulonglong>(
                                        blobs.size())));
                            }
                            for (const auto& b : blobs) {
                                wrap_peer_send(
                                    fb::proto::PeerEnvelope::OFFLINE_DELIVERY,
                                    from,
                                    std::span<const std::uint8_t>(
                                        b.data(), b.size()));
                            }
                            break;
                        }
                        case fb::proto::PeerEnvelope::OFFLINE_DELIVERY: {
                            // A relay is delivering a queued blob to
                            // us. The blob is a wire-form Envelope
                            // we can decrypt the same way as direct
                            // DM delivery.
                            fb::proto::Envelope inner;
                            if (!inner.ParseFromArray(
                                    payload.data(),
                                    static_cast<int>(payload.size()))) {
                                break;
                            }
                            if (try_decrypt_dm_text(inner)) {
                                emit log("DM (offline-relay) "
                                          "decrypted");
                            }
                            break;
                        }
                        default: break;
                    }
                }

                // 0b. Periodic maintenance ticks.
                {
                    const auto t = now_ms();
                    if (t - impl_->last_self_publish_ms
                            >= kRepublishIntervalMs) {
                        impl_->last_self_publish_ms = t;
                        republish_self();
                    }
                    if (t - impl_->last_gossip_pull_ms
                            >= kGossipPullIntervalMs) {
                        impl_->last_gossip_pull_ms = t;
                        gossip_pull_round();
                    }
                }

                // 0. Drain pending channel ops.
                std::deque<PendingChannelOp> chan_ops;
                {
                    std::lock_guard lk(impl_->mu);
                    chan_ops.swap(impl_->chan_queue);
                }
                for (auto& op : chan_ops) {
                    auto& cs = impl_->channels[op.channel_name];
                    if (cs.id[0] == 0 && cs.id[1] == 0 && cs.id[2] == 0) {
                        cs.id = channel_id_from_name(op.channel_name);
                        impl_->chan_id_to_name[std::string(
                            reinterpret_cast<const char*>(cs.id.data()), cs.id.size())] =
                            op.channel_name;
                    }
                    auto subscribe_now = [&]() {
                        if (cs.subscribed) return;
                        fb::proto::Frame f;
                        f.mutable_chan_subscribe()->set_channel_group_id(
                            std::string(reinterpret_cast<const char*>(cs.id.data()),
                                        cs.id.size()));
                        blocking_send(impl_->conn, serialize(f));
                        cs.subscribed = true;
                        // I3: also subscribe via gossipsub when
                        // P2PNode is configured. Channel envelope
                        // fan-out then works without a central
                        // server (each member who's subscribed
                        // receives via gossip flood).
                        if (impl_->gossip) {
                            const auto topic =
                                fb::p2p::channel_topic_name(
                                    std::span<const std::uint8_t>(
                                        cs.id.data(), cs.id.size()));
                            impl_->gossip->subscribe(topic);
                            emit log(QString("gossip subscribed to "
                                              "channel topic %1")
                                         .arg(QString::fromStdString(
                                             topic.substr(0, 24)) + "…"));
                        }
                        emit channelJoined(QString::fromStdString(op.channel_name));
                        emit log(QString("subscribed to channel #%1")
                                     .arg(QString::fromStdString(op.channel_name)));
                    };
                    if (op.kind == PendingChannelOp::Kind::kCreate) {
                        try {
                            cs.own_dist = cs.session->create_own_send_chain();
                            write_file_bytes(op.dist_path,
                                             std::span<const std::uint8_t>(cs.own_dist.data(),
                                                                            cs.own_dist.size()));
                            emit log(QString("created channel #%1 — distribution at %2")
                                         .arg(QString::fromStdString(op.channel_name))
                                         .arg(QString::fromStdString(op.dist_path)));
                            subscribe_now();
                            persist_chan_meta(op.channel_name, cs);
                            persist_chan_session(op.channel_name, cs);
                        } catch (const std::exception& e) {
                            emit errorOccurred(
                                QString("create channel failed: %1").arg(e.what()));
                        }
                    } else if (op.kind == PendingChannelOp::Kind::kCreateLocal) {
                        // Lightweight create: own SenderKeys chain + subscribe,
                        // but no distribution file and no peer DM. The user
                        // invites peers separately via the Invite button.
                        try {
                            if (cs.own_dist.empty()) {
                                cs.own_dist = cs.session->create_own_send_chain();
                            }
                            // Record the per-channel cipher choice. Even
                            // for an MLS channel we keep the SenderKeys
                            // distribution around — it's small, harmless,
                            // and lets the receive path fall back if a
                            // peer hasn't migrated yet.
                            cs.crypto = op.use_mls
                                ? fb::store::SqliteStore::ChannelCrypto::kMls
                                : fb::store::SqliteStore::ChannelCrypto::kSenderKeys;
                            if (op.use_mls) {
                                // Create a fresh single-member MLS group
                                // with us as the founder. The same
                                // channel_id we derived above is the MLS
                                // group_id — they're 32 bytes so the
                                // mapping is direct, and using the same
                                // value keeps server-side routing
                                // unchanged for MLS channels.
                                if (cs.id[0] == 0 && cs.id[1] == 0) {
                                    cs.id = channel_id_from_name(op.channel_name);
                                }
                                try {
                                    cs.mls = fb::crypto::MlsGroup::create(
                                        std::span<const std::uint8_t, 32>(
                                            impl_->identity->public_key().data(), 32),
                                        std::span<const std::uint8_t, 32>(
                                            cs.id.data(), 32));
                                    // Persist the seed BEFORE returning
                                    // success — if the process dies
                                    // between create and the first
                                    // commit, the empty group is still
                                    // restorable.
                                    persist_mls_seed(cs);
                                } catch (const std::exception& e) {
                                    emit errorOccurred(QString(
                                        "MLS create failed: %1 — falling back to "
                                        "SenderKeys for #%2").arg(e.what())
                                        .arg(QString::fromStdString(op.channel_name)));
                                    cs.crypto =
                                        fb::store::SqliteStore::ChannelCrypto::kSenderKeys;
                                }
                            }
                            subscribe_now();
                            persist_chan_meta(op.channel_name, cs);
                            persist_chan_session(op.channel_name, cs);
                            emit log(QString("created local channel #%1 (%2, no peers yet)")
                                         .arg(QString::fromStdString(op.channel_name))
                                         .arg(op.use_mls ? "MLS" : "SenderKeys"));
                        } catch (const std::exception& e) {
                            emit errorOccurred(
                                QString("create channel failed: %1").arg(e.what()));
                        }
                    } else if (op.kind == PendingChannelOp::Kind::kJoin) {
                        try {
                            auto dist_blob = read_file_bytes(op.dist_path);
                            cs.own_dist = std::move(dist_blob);
                            // Stage the dist for installation when the first
                            // inbound channel envelope arrives (we still
                            // don't know the *sender* pubkey here — Phase 1
                            // simplification: every channel msg carries
                            // sender_pubkey in the envelope so we install
                            // lazily per-sender on first sight).
                            emit log(QString("joined channel #%1 from %2")
                                         .arg(QString::fromStdString(op.channel_name))
                                         .arg(QString::fromStdString(op.dist_path)));
                            subscribe_now();
                            persist_chan_meta(op.channel_name, cs);
                            persist_chan_session(op.channel_name, cs);
                        } catch (const std::exception& e) {
                            emit errorOccurred(
                                QString("join channel failed: %1").arg(e.what()));
                        }
                    } else if (op.kind == PendingChannelOp::Kind::kSend) {
                        if (cs.own_dist.empty()) {
                            emit errorOccurred(
                                QString("cannot send to #%1: not created/joined yet")
                                    .arg(QString::fromStdString(op.channel_name)));
                            continue;
                        }
                        try {
                            std::vector<std::uint8_t> pt(op.text.begin(), op.text.end());
                            std::vector<std::uint8_t> envid(16);
                            randombytes_buf(envid.data(), envid.size());
                            const auto now_ms = static_cast<std::uint64_t>(
                                std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count());
                            const auto env_aad = envelope_aad_bytes(
                                std::span<const std::uint8_t>(envid.data(), envid.size()),
                                now_ms);
                            // Branch on per-channel cipher: MLS channels
                            // route the plaintext through MlsGroup::
                            // application_encrypt; SenderKeys channels
                            // keep using the existing GroupSession.
                            // env_aad isn't bound by mls::Session::protect
                            // (mlspp computes its own internal AAD over
                            // the MLSCiphertext header) — for MLS we
                            // leave Envelope.aad empty so receivers don't
                            // mismatch; for SenderKeys it's bound as
                            // before.
                            std::vector<std::uint8_t> inner;
                            const bool use_mls =
                                cs.crypto == fb::store::SqliteStore::ChannelCrypto::kMls
                                && cs.mls;
                            if (use_mls) {
                                inner = cs.mls->application_encrypt(
                                    std::span<const std::uint8_t>(pt.data(), pt.size()));
                            } else {
                                inner = cs.session->encrypt(
                                    std::span<const std::uint8_t>(pt.data(), pt.size()),
                                    std::span<const std::uint8_t>(env_aad.data(),
                                                                    env_aad.size()));
                            }
                            fb::proto::Frame f;
                            auto* env = f.mutable_envelope();
                            env->set_envelope_id(std::string(envid.begin(), envid.end()));
                            env->set_timestamp_ms(now_ms);
                            // Skip Envelope.aad for MLS — mls::Session
                            // covers its own AAD internally; populating
                            // Envelope.aad would make receivers reject
                            // the message at the cross-check.
                            if (!use_mls) {
                                env->set_aad(std::string(env_aad.begin(), env_aad.end()));
                            }
                            env->set_channel_group_id(std::string(
                                reinterpret_cast<const char*>(cs.id.data()), cs.id.size()));
                            env->set_sender_pubkey(std::string(
                                reinterpret_cast<const char*>(
                                    impl_->identity->public_key().data()),
                                impl_->identity->public_key().size()));
                            env->set_ciphertext(std::string(inner.begin(), inner.end()));
                            env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
                            env->set_protocol_version(fb::config::kProtocolVersion);
                            blocking_send(impl_->conn, serialize(f));
                            // Persist channel state so the advanced send-chain
                            // survives a restart (own_next_index, own_chain_key).
                            persist_chan_session(op.channel_name, cs);
                            // Persist sent channel message for history replay.
                            if (impl_->store) {
                                const auto now_ms = static_cast<std::uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
                                impl_->store->chan_append_inbox(
                                    std::span<const std::uint8_t>(cs.id.data(), cs.id.size()),
                                    std::span<const std::uint8_t>(
                                        impl_->identity->public_key().data(), 32),
                                    std::span<const std::uint8_t>(pt.data(), pt.size()),
                                    now_ms);
                            }
                            emit log(QString("sent %1B to #%2")
                                         .arg(pt.size())
                                         .arg(QString::fromStdString(op.channel_name)));
                        } catch (const std::exception& e) {
                            emit errorOccurred(
                                QString("channel send failed: %1").arg(e.what()));
                        }
                    } else if (op.kind == PendingChannelOp::Kind::kLeave) {
                        // ChannelUnsubscribe over the wire so the server stops
                        // fanning out for us, then drop everything on disk.
                        if (cs.subscribed) {
                            fb::proto::Frame uf;
                            uf.mutable_chan_unsubscribe()->set_channel_group_id(
                                std::string(reinterpret_cast<const char*>(cs.id.data()),
                                            cs.id.size()));
                            blocking_send(impl_->conn, serialize(uf));
                        }
                        if (impl_->store) {
                            impl_->store->chan_delete(
                                op.channel_name,
                                std::span<const std::uint8_t>(cs.id.data(), cs.id.size()));
                        }
                        impl_->chan_id_to_name.erase(std::string(
                            reinterpret_cast<const char*>(cs.id.data()), cs.id.size()));
                        impl_->channels.erase(op.channel_name);
                        emit log(QString("left #%1 (sidebar entry, sessions, persisted state "
                                         "all cleared)")
                                     .arg(QString::fromStdString(op.channel_name)));
                    } else if (op.kind == PendingChannelOp::Kind::kRoomJoin) {
                        // Group-call signaling: announce ourselves to the
                        // room. Server replies with RoomRoster broadcasts
                        // (handled in the read loop) on every membership
                        // change. The room_id IS the channel_group_id —
                        // ensure the channel exists before joining.
                        if (cs.id[0] == 0 && cs.id[1] == 0) {
                            cs.id = channel_id_from_name(op.channel_name);
                        }
                        fb::proto::Frame jf;
                        auto* rj = jf.mutable_room_join();
                        rj->set_room_id(std::string(
                            reinterpret_cast<const char*>(cs.id.data()), cs.id.size()));
                        rj->set_want_audio(true);
                        rj->set_want_video(op.want_video);
                        blocking_send(impl_->conn, serialize(jf));
                        emit log(QString("joined call on #%1 (video=%2)")
                                     .arg(QString::fromStdString(op.channel_name))
                                     .arg(op.want_video ? "yes" : "no"));
                    } else if (op.kind == PendingChannelOp::Kind::kRoomLeave) {
                        if (cs.id[0] == 0 && cs.id[1] == 0) {
                            cs.id = channel_id_from_name(op.channel_name);
                        }
                        fb::proto::Frame lf;
                        lf.mutable_room_leave()->set_room_id(std::string(
                            reinterpret_cast<const char*>(cs.id.data()), cs.id.size()));
                        blocking_send(impl_->conn, serialize(lf));
                        emit log(QString("left call on #%1")
                                     .arg(QString::fromStdString(op.channel_name)));
                    } else if (op.kind == PendingChannelOp::Kind::kInvite) {
                        // Route based on the channel's per-channel cipher.
                        // For MLS channels we send an MlsInviteRequest
                        // (the four-step in-band handshake from step D);
                        // for SenderKeys channels we keep the existing
                        // channel-key DM-distribution flow.
                        if (cs.crypto ==
                            fb::store::SqliteStore::ChannelCrypto::kMls) {
                            // Build + enqueue MlsInviteRequest payload.
                            // Channel id derived from name to match
                            // create_local_channel's id derivation.
                            if (cs.id[0] == 0 && cs.id[1] == 0) {
                                cs.id = channel_id_from_name(op.channel_name);
                            }
                            auto invite_payload =
                                pack_mls_invite_request_payload(
                                    std::span<const std::uint8_t>(
                                        cs.id.data(), cs.id.size()),
                                    op.channel_name);
                            PendingSend ps;
                            ps.peer = op.peer;
                            ps.pre_packed_payload = std::move(invite_payload);
                            {
                                std::lock_guard lk(impl_->mu);
                                impl_->queue.push_back(std::move(ps));
                            }
                            impl_->cv.notify_all();
                            emit log(QString("MLS invite-request queued: "
                                              "%1 → #%2")
                                         .arg(QString::fromStdString(op.peer))
                                         .arg(QString::fromStdString(op.channel_name)));
                            continue;
                        }
                        // SenderKeys path (default): in-band invite — ensure
                        // we have a chain, then queue a DM to `peer`
                        // carrying the channel-key payload.
                        if (cs.own_dist.empty()) {
                            try {
                                cs.own_dist = cs.session->create_own_send_chain();
                                emit log(QString("created channel #%1 for invite")
                                             .arg(QString::fromStdString(op.channel_name)));
                            } catch (const std::exception& e) {
                                emit errorOccurred(
                                    QString("channel create-for-invite failed: %1")
                                        .arg(e.what()));
                                continue;
                            }
                        }
                        subscribe_now();
                        // Queue a DM with the channel-key payload. We piggy-
                        // back on the existing send_to_peer pipeline (which
                        // packs DmPayload{text}) by pushing a *raw* DM here
                        // with a sentinel — actually simpler: enqueue
                        // directly via the same path with a special marker.
                        // The cleanest path is to inline it: build the
                        // ratchet message and send right here, since we
                        // already have access to sessions[peer].
                        auto& peer_sess = impl_->sessions[op.peer];
                        if (!peer_sess.rat) {
                            // Trigger prekey fetch like normal send-to-peer
                            // would; then re-queue the invite for retry.
                            fb::proto::Frame f;
                            f.mutable_key_fetch()->set_username(op.peer);
                            blocking_send(impl_->conn, serialize(f));
                            emit log(QString("fetching prekey for %1 to deliver invite")
                                         .arg(QString::fromStdString(op.peer)));
                            std::lock_guard lk(impl_->mu);
                            impl_->pending_fetch_targets.push_back(op.peer);
                            impl_->chan_queue.push_front(std::move(op));
                            break;
                        }
                        auto pt = pack_channel_key_payload(
                            std::span<const std::uint8_t>(cs.id.data(), cs.id.size()),
                            op.channel_name,
                            std::span<const std::uint8_t>(cs.own_dist.data(),
                                                           cs.own_dist.size()));
                        std::vector<std::uint8_t> envid(16);
                        randombytes_buf(envid.data(), envid.size());
                        const auto now_ms = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count());
                        const auto env_aad = envelope_aad_bytes(
                            std::span<const std::uint8_t>(envid.data(), envid.size()),
                            now_ms);
                        auto inner = peer_sess.rat->encrypt(
                            std::span<const std::uint8_t>(pt.data(), pt.size()),
                            std::span<const std::uint8_t>(env_aad.data(),
                                                            env_aad.size()));
                        fb::proto::Frame f;
                        auto* env = f.mutable_envelope();
                        env->set_envelope_id(std::string(envid.begin(), envid.end()));
                        env->set_timestamp_ms(now_ms);
                        env->set_aad(std::string(env_aad.begin(), env_aad.end()));
                        env->set_user_pubkey(std::string(
                            reinterpret_cast<const char*>(peer_sess.peer_pub.data()),
                            peer_sess.peer_pub.size()));
                        env->set_sender_pubkey(std::string(
                            reinterpret_cast<const char*>(
                                impl_->identity->public_key().data()),
                            impl_->identity->public_key().size()));
                        env->set_ciphertext(std::string(inner.begin(), inner.end()));
                        env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
                        env->set_protocol_version(fb::config::kProtocolVersion);
                        blocking_send(impl_->conn, serialize(f));
                        // Persist channel meta (own_dist may be brand-new).
                        persist_chan_meta(op.channel_name, cs);
                        persist_chan_session(op.channel_name, cs);
                        emit log(QString("invited %1 to #%2")
                                     .arg(QString::fromStdString(op.peer))
                                     .arg(QString::fromStdString(op.channel_name)));
                    }
                }

                // 1a. Drain pending media-signal sends.
                {
                    std::deque<PendingMediaSignal> ms;
                    {
                        std::lock_guard lk(impl_->mu);
                        ms.swap(impl_->media_queue);
                    }
                    for (auto& sig : ms) {
                        // Find the per-peer ratchet session by pubkey.
                        Impl::Session* sess = nullptr;
                        for (auto& [name, s] : impl_->sessions) {
                            if (s.peer_pub == sig.peer_pub) { sess = &s; break; }
                        }
                        if (!sess || !sess->rat) {
                            fb::crypto::PubKey want{};
                            std::memcpy(want.data(), sig.peer_pub.data(), 32);
                            const QString want_fp = QString::fromStdString(
                                fb::crypto::Identity::fingerprint(want));
                            emit log(QString("media signal dropped — no session "
                                             "for peer (kind=%1 want_fp=%2 sessions=%3)")
                                         .arg(sig.kind).arg(want_fp)
                                         .arg(impl_->sessions.size()));
                            continue;
                        }
                        auto pt = pack_media_signal_payload(
                            std::span<const std::uint8_t, 16>(sig.call_id.data(), 16),
                            sig.kind,
                            std::span<const std::uint8_t>(sig.payload.data(), sig.payload.size()),
                            sig.epoch);
                        std::vector<std::uint8_t> envid(16);
                        randombytes_buf(envid.data(), envid.size());
                        const auto now_ms = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count());
                        const auto env_aad = envelope_aad_bytes(
                            std::span<const std::uint8_t>(envid.data(), envid.size()),
                            now_ms);
                        auto inner = sess->rat->encrypt(
                            std::span<const std::uint8_t>(pt.data(), pt.size()),
                            std::span<const std::uint8_t>(env_aad.data(),
                                                            env_aad.size()));
                        fb::proto::Frame f;
                        auto* env = f.mutable_envelope();
                        env->set_envelope_id(std::string(envid.begin(), envid.end()));
                        env->set_timestamp_ms(now_ms);
                        env->set_aad(std::string(env_aad.begin(), env_aad.end()));
                        env->set_user_pubkey(std::string(
                            reinterpret_cast<const char*>(sig.peer_pub.data()),
                            sig.peer_pub.size()));
                        env->set_sender_pubkey(std::string(
                            reinterpret_cast<const char*>(impl_->identity->public_key().data()),
                            impl_->identity->public_key().size()));
                        env->set_ciphertext(std::string(inner.begin(), inner.end()));
                        env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
                        env->set_protocol_version(fb::config::kProtocolVersion);
                        blocking_send(impl_->conn, serialize(f));
                    }
                }

                // 1. Drain pending sends.
                std::deque<PendingSend> to_send;
                {
                    std::lock_guard lk(impl_->mu);
                    to_send.swap(impl_->queue);
                }
                for (auto& s : to_send) {
                    // If the target looks like a fingerprint ("XXXXX-XXXXX")
                    // — which is what the UI puts in the field when the user
                    // replies to a peer whose username hasn't resolved yet —
                    // try to find an existing session whose peer_pub matches
                    // the fingerprint, and rebind this send to that session's
                    // original key. Without this, key_fetch goes out for the
                    // fingerprint-as-username, the server returns not-found,
                    // and the failsafe fires "no such user" even though we
                    // already have a working ratchet for the actual peer.
                    if (s.peer.size() == 11 && s.peer[5] == '-' &&
                        !impl_->sessions.count(s.peer)) {
                        for (const auto& [name, sess_existing] : impl_->sessions) {
                            if (!sess_existing.rat) continue;
                            fb::crypto::PubKey pk{};
                            std::memcpy(pk.data(), sess_existing.peer_pub.data(), 32);
                            if (fb::crypto::Identity::fingerprint(pk) == s.peer) {
                                emit log(QString("rebinding reply: fp %1 -> session '%2'")
                                             .arg(QString::fromStdString(s.peer))
                                             .arg(QString::fromStdString(name)));
                                s.peer = name;
                                break;
                            }
                        }
                    }
                    auto& sess = impl_->sessions[s.peer];
                    if (!sess.rat) {
                        // Need to fetch peer bundle first.
                        fb::proto::Frame f;
                        f.mutable_key_fetch()->set_username(s.peer);
                        blocking_send(impl_->conn, serialize(f));
                        emit log(QString("fetching prekey for %1")
                                     .arg(QString::fromStdString(s.peer)));
                        // Re-enqueue; we'll handle the response in the read
                        // loop and re-try.
                        std::lock_guard lk(impl_->mu);
                        impl_->pending_fetch_targets.push_back(s.peer);
                        impl_->queue.push_front(std::move(s));
                        break;
                    }
                    // Wrap as DmPayload{text} so receivers can disambiguate
                    // text from channel-key invites — UNLESS the caller
                    // already supplied a pre-packed payload (the MLS
                    // handshake sends use this to ride the same ratchet
                    // without needing a parallel queue).
                    auto pt = s.has_pre_packed()
                        ? std::move(s.pre_packed_payload)
                        : pack_text_payload(s.text);
                    std::vector<std::uint8_t> envid(16);
                    randombytes_buf(envid.data(), envid.size());
                    const auto now_ms = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                    const auto env_aad = envelope_aad_bytes(
                        std::span<const std::uint8_t>(envid.data(), envid.size()),
                        now_ms);
                    auto inner = sess.rat->encrypt(
                        std::span<const std::uint8_t>(pt.data(), pt.size()),
                        std::span<const std::uint8_t>(env_aad.data(),
                                                        env_aad.size()));
                    fb::proto::Frame f;
                    auto* env = f.mutable_envelope();
                    env->set_envelope_id(std::string(envid.begin(), envid.end()));
                    env->set_timestamp_ms(now_ms);
                    env->set_aad(std::string(env_aad.begin(), env_aad.end()));
                    env->set_user_pubkey(std::string(
                        reinterpret_cast<const char*>(sess.peer_pub.data()),
                        sess.peer_pub.size()));
                    env->set_sender_pubkey(std::string(
                        reinterpret_cast<const char*>(impl_->identity->public_key().data()),
                        impl_->identity->public_key().size()));
                    env->set_ciphertext(std::string(inner.begin(), inner.end()));
                    env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
                    env->set_protocol_version(fb::config::kProtocolVersion);
                    blocking_send(impl_->conn, serialize(f));
                    if (impl_->store && !s.text.empty()) {
                        // Persist the original text bytes (not the wrapped
                        // DmPayload blob) so on-disk history is human-
                        // readable. Skip pre-packed sends entirely —
                        // those are protocol-internal MLS handshake
                        // messages, not user chat.
                        std::vector<std::uint8_t> raw_text(s.text.begin(), s.text.end());
                        impl_->store->append_outbox(
                            std::span<const std::uint8_t>(envid.data(), envid.size()),
                            std::span<const std::uint8_t>(sess.peer_pub.data(),
                                                          sess.peer_pub.size()),
                            std::span<const std::uint8_t>(raw_text.data(), raw_text.size()),
                            now_ms);
                        // Remember the username we used to send to this pubkey
                        // so the sidebar's DM list survives a restart.
                        impl_->store->cache_peer_name(
                            std::span<const std::uint8_t>(sess.peer_pub.data(),
                                                          sess.peer_pub.size()),
                            s.peer);
                    }
                    emit log(QString("sent %1B to %2%3")
                                 .arg(static_cast<qulonglong>(
                                     s.text.empty() ? pt.size() : s.text.size()))
                                 .arg(QString::fromStdString(s.peer))
                                 .arg(s.text.empty() ? " (mls protocol msg)" : ""));
                }

                // 2. Read with short timeout. Conn::read_some
                // unifies plain TCP and TLS — 0 means timeout or
                // peer-closed; >0 means bytes available.
                {
                    auto n = conn_read_with_timeout(impl_->conn,
                        std::span<std::uint8_t>(rxbuf.data(), rxbuf.size()),
                        100);
                if (n > 0) {
                    impl_->dec.feed(std::span<const std::uint8_t>(
                        rxbuf.data(), n));
                    std::vector<std::uint8_t> frame;
                    while (impl_->dec.try_pop(frame) ==
                           fb::net::FrameDecoder::Status::kFrameReady) {
                        fb::proto::Frame f;
                        if (!f.ParseFromArray(frame.data(),
                                              static_cast<int>(frame.size()))) {
                            continue;
                        }
                        if (f.body_case() == fb::proto::Frame::kControl) {
                            const auto& cm = f.control();
                            if (cm.code() == fb::proto::ControlMessage::USERNAME_TAKEN) {
                                emit errorOccurred(
                                    QString("This username is already registered to a "
                                            "different identity on the server. Sign out "
                                            "and pick a different name (or restore the "
                                            "original identity from its recovery code)."));
                                impl_->stop_requested = true;
                            }
                            continue;
                        }
                        if (f.body_case() == fb::proto::Frame::kPeer) {
                            // Inbound overlay envelope from another
                            // peer (server forwarded by recipient
                            // pubkey). Dispatch by kind to the right
                            // overlay object.
                            const auto& pe = f.peer();
                            fb::p2p::PeerInfo from{};
                            if (pe.sender_pubkey().size() == 32) {
                                from.id = fb::p2p::node_id_from_pubkey(
                                    std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(
                                            pe.sender_pubkey().data()),
                                        32));
                                from.pubkey.assign(
                                    pe.sender_pubkey().begin(),
                                    pe.sender_pubkey().end());
                                // Touch the routing table — every
                                // sender we hear from is a viable
                                // peer for our DHT lookups.
                                if (impl_->dht) impl_->dht->observe(from);
                            }
                            auto payload = std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t*>(
                                    pe.payload().data()),
                                pe.payload().size());
                            switch (pe.kind()) {
                                case fb::proto::PeerEnvelope::DHT:
                                    if (impl_->dht) {
                                        impl_->dht->on_message(from, payload);
                                    }
                                    break;
                                case fb::proto::PeerEnvelope::GOSSIP:
                                    if (impl_->username_gossip) {
                                        impl_->username_gossip->on_message(
                                            from, payload);
                                    }
                                    break;
                                case fb::proto::PeerEnvelope::DM: {
                                    fb::proto::Envelope inner;
                                    if (!inner.ParseFromArray(
                                            payload.data(),
                                            static_cast<int>(payload.size()))) {
                                        break;
                                    }
                                    if (try_decrypt_dm_text(inner)) {
                                        emit log("DM (server-relay) "
                                                  "decrypted via I1");
                                    }
                                    break;
                                }
                                case fb::proto::PeerEnvelope::OFFLINE_DEPOSIT: {
                                    if (!impl_->offline_store) break;
                                    const auto& rec = pe.recipient_pubkey();
                                    if (rec.size() != 32) break;
                                    impl_->offline_store->deposit(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                rec.data()), 32),
                                        payload);
                                    break;
                                }
                                case fb::proto::PeerEnvelope::OFFLINE_FETCH: {
                                    if (!impl_->offline_store) break;
                                    if (from.pubkey.size() != 32) break;
                                    auto blobs = impl_->offline_store
                                        ->fetch_and_clear(
                                            std::span<const std::uint8_t>(
                                                from.pubkey.data(),
                                                from.pubkey.size()));
                                    for (const auto& b : blobs) {
                                        wrap_peer_send(
                                            fb::proto::PeerEnvelope::OFFLINE_DELIVERY,
                                            from,
                                            std::span<const std::uint8_t>(
                                                b.data(), b.size()));
                                    }
                                    break;
                                }
                                case fb::proto::PeerEnvelope::OFFLINE_DELIVERY: {
                                    fb::proto::Envelope inner;
                                    if (!inner.ParseFromArray(
                                            payload.data(),
                                            static_cast<int>(payload.size()))) {
                                        break;
                                    }
                                    if (try_decrypt_dm_text(inner)) {
                                        emit log("DM (offline-relay) "
                                                  "decrypted");
                                    }
                                    break;
                                }
                                default:
                                    break;
                            }
                            continue;
                        }
                        if (f.body_case() == fb::proto::Frame::kRoomRoster) {
                            const auto& rr = f.room_roster();
                            if (rr.room_id().size() != 32) continue;
                            // Resolve the room_id back to a channel name —
                            // it's the channel's group_id verbatim.
                            std::array<std::uint8_t, 32> rid{};
                            std::memcpy(rid.data(), rr.room_id().data(), 32);
                            auto nit = impl_->chan_id_to_name.find(
                                std::string(rr.room_id().begin(), rr.room_id().end()));
                            QString chan_name;
                            if (nit != impl_->chan_id_to_name.end()) {
                                chan_name = QString::fromStdString(nit->second);
                            }
                            QStringList fps;
                            for (const auto& p : rr.participants()) {
                                if (p.identity_pubkey().size() != 32) continue;
                                fb::crypto::PubKey k{};
                                std::memcpy(k.data(), p.identity_pubkey().data(), 32);
                                fps << QString::fromStdString(
                                    fb::crypto::Identity::fingerprint(k));
                            }
                            emit log(QString("room roster for #%1: %2 participant(s)")
                                         .arg(chan_name.isEmpty() ? "<unknown>" : chan_name)
                                         .arg(fps.size()));
                            emit channelCallRoster(chan_name, fps);

                            // Mesh-dial: build the set of OTHER participants
                            // in the room, diff against who we've already
                            // dialed/accepted, and dispatch start_call_to_pub
                            // on the Qt main thread for each new peer where
                            // we're on the higher side of the pubkey
                            // tiebreak (the lower side waits for our OFFER).
                            // Departed peers get their MediaCall hung up.
                            std::set<std::string> roster_peer_keys;
                            std::vector<std::array<std::uint8_t, 32>> to_dial;
                            const std::string room_id_str(rr.room_id().begin(),
                                                           rr.room_id().end());
                            const auto& my_pub = impl_->identity->public_key();
                            for (const auto& p : rr.participants()) {
                                if (p.identity_pubkey().size() != 32) continue;
                                if (std::equal(my_pub.begin(), my_pub.end(),
                                               p.identity_pubkey().begin())) {
                                    continue;   // skip self
                                }
                                roster_peer_keys.insert(std::string(
                                    p.identity_pubkey().begin(),
                                    p.identity_pubkey().end()));
                            }
                            auto& meshed = impl_->room_mesh_peers[room_id_str];
                            // Hang up calls for peers that left.
                            std::vector<std::string> to_drop;
                            for (const auto& peer_key : meshed) {
                                if (!roster_peer_keys.count(peer_key)) {
                                    to_drop.push_back(peer_key);
                                }
                            }
                            for (const auto& peer_key : to_drop) {
                                meshed.erase(peer_key);
                                MediaCall* call = nullptr;
                                {
                                    auto it = impl_->calls_by_peer.find(peer_key);
                                    if (it != impl_->calls_by_peer.end()) {
                                        call = it->second.call;
                                    }
                                }
                                if (call) {
                                    QMetaObject::invokeMethod(call, [call]() {
                                        call->hangup();
                                    }, Qt::QueuedConnection);
                                }
                            }
                            // Dial new peers (only on the higher-pubkey side).
                            for (const auto& peer_key : roster_peer_keys) {
                                if (meshed.count(peer_key)) continue;
                                std::array<std::uint8_t, 32> peer_pub_arr{};
                                std::memcpy(peer_pub_arr.data(),
                                            peer_key.data(), 32);
                                const bool i_dial = std::lexicographical_compare(
                                    peer_pub_arr.begin(), peer_pub_arr.end(),
                                    my_pub.begin(), my_pub.end());
                                meshed.insert(peer_key);   // claim it either way
                                if (!i_dial) continue;     // wait for inbound
                                fb::crypto::PubKey arr{};
                                std::memcpy(arr.data(), peer_pub_arr.data(), 32);
                                const QString fp_label = QString::fromStdString(
                                    fb::crypto::Identity::fingerprint(arr));
                                // Decide here whether we have a usable session
                                // for this peer or need to bootstrap one. If
                                // bootstrap, queue the username_lookup right
                                // now — the response handler will follow
                                // through with key_fetch and ultimately
                                // re-dispatch start_call_to_pub.
                                bool have_session = false;
                                for (const auto& [_, s] : impl_->sessions) {
                                    if (s.rat && s.peer_pub == peer_pub_arr) {
                                        have_session = true;
                                        break;
                                    }
                                }
                                if (have_session) {
                                    to_dial.push_back(peer_pub_arr);
                                    emit log(QString("mesh-dial: room #%1 → %2")
                                                 .arg(chan_name).arg(fp_label));
                                } else {
                                    Impl::PendingMeshDial pd;
                                    pd.room_id    = room_id_str;
                                    pd.with_video = false;
                                    pd.label      = fp_label;
                                    impl_->pending_mesh_dials[peer_key] = pd;
                                    fb::proto::Frame qf;
                                    qf.mutable_username_lookup()->set_pubkey(
                                        std::string(peer_key.begin(), peer_key.end()));
                                    blocking_send(impl_->conn, serialize(qf));
                                    emit log(QString("mesh-bootstrap: %1 has no "
                                                      "session yet, resolving "
                                                      "username for key fetch")
                                                 .arg(fp_label));
                                }
                            }
                            // Dispatch dials on the main thread.
                            for (const auto& peer_pub_arr : to_dial) {
                                std::array<std::uint8_t, 32> pub_copy = peer_pub_arr;
                                fb::crypto::PubKey arr{};
                                std::memcpy(arr.data(), pub_copy.data(), 32);
                                const QString label = QString::fromStdString(
                                    fb::crypto::Identity::fingerprint(arr));
                                std::string room_copy = room_id_str;
                                QMetaObject::invokeMethod(this,
                                    [this, pub_copy, label, room_copy]() {
                                        if (!start_call_to_pub(
                                                pub_copy, label,
                                                /*with_video=*/false, room_copy)) {
                                            emit log(QString(
                                                "mesh-dial: already calling %1")
                                                .arg(label));
                                        }
                                    }, Qt::QueuedConnection);
                            }
                            continue;
                        }
                        if (f.body_case() == fb::proto::Frame::kUsernameResp) {
                            const auto& r = f.username_resp();
                            if (r.found() && r.pubkey().size() == 32 &&
                                !r.username().empty()) {
                                std::vector<std::uint8_t> pk(r.pubkey().begin(),
                                                              r.pubkey().end());
                                if (impl_->store) {
                                    impl_->store->cache_peer_name(
                                        std::span<const std::uint8_t>(pk.data(), pk.size()),
                                        r.username());
                                }
                                fb::crypto::PubKey arr{};
                                std::memcpy(arr.data(), pk.data(), 32);
                                emit peerUsernameResolved(
                                    QString::fromStdString(
                                        fb::crypto::Identity::fingerprint(arr)),
                                    QString::fromStdString(r.username()));
                                // Mesh-bootstrap step 2: if we asked who this
                                // peer is because we want to mesh-dial them,
                                // follow through with a key_fetch now that we
                                // have a username. The kKeyFetchResp success
                                // path will retry start_call_to_pub once the
                                // session is up.
                                const std::string peer_pub_str(r.pubkey().begin(),
                                                                r.pubkey().end());
                                if (impl_->pending_mesh_dials.count(peer_pub_str)) {
                                    fb::proto::Frame kf;
                                    kf.mutable_key_fetch()->set_username(r.username());
                                    blocking_send(impl_->conn, serialize(kf));
                                    impl_->pending_fetch_targets.push_back(r.username());
                                    impl_->mesh_bootstrap_pending[r.username()] =
                                        peer_pub_str;
                                    emit log(QString("mesh-bootstrap: fetching "
                                                      "prekey for %1")
                                                 .arg(QString::fromStdString(
                                                     r.username())));
                                }
                            } else if (r.pubkey().size() == 32) {
                                // username_lookup returned NOT_FOUND for a
                                // peer we wanted to dial. Drop the pending
                                // bootstrap so we don't leak state.
                                const std::string peer_pub_str(r.pubkey().begin(),
                                                                r.pubkey().end());
                                if (impl_->pending_mesh_dials.erase(peer_pub_str)) {
                                    emit log("mesh-bootstrap: server doesn't "
                                              "know this peer — giving up");
                                }
                            }
                            continue;
                        }
                        if (f.body_case() == fb::proto::Frame::kKeyFetchResp) {
                            const auto& r = f.key_fetch_resp();
                            // Pull the username this fetch was for off the
                            // FIFO. Both DM-send and channel-invite paths
                            // record their fetches here, so this works
                            // whichever path triggered the lookup.
                            std::string fetched_for;
                            {
                                std::lock_guard lk(impl_->mu);
                                if (!impl_->pending_fetch_targets.empty()) {
                                    fetched_for = impl_->pending_fetch_targets.front();
                                    impl_->pending_fetch_targets.pop_front();
                                }
                            }
                            if (fetched_for.empty()) {
                                emit log("key_fetch_resp without an in-flight fetch — "
                                          "ignoring");
                                continue;
                            }
                            if (!r.found() || r.bundle().identity_pubkey().size() != 32 ||
                                r.bundle().signed_prekey().size() != 32) {
                                // Failsafe — drop every queued op (DM or
                                // invite) targeting this nonexistent peer
                                // so we don't loop firing key_fetch forever,
                                // then surface a single error to the UI.
                                std::size_t dm_dropped = 0, inv_dropped = 0;
                                {
                                    std::lock_guard lk(impl_->mu);
                                    auto qend = std::remove_if(
                                        impl_->queue.begin(), impl_->queue.end(),
                                        [&](const PendingSend& s){
                                            return s.peer == fetched_for;
                                        });
                                    dm_dropped = static_cast<std::size_t>(
                                        std::distance(qend, impl_->queue.end()));
                                    impl_->queue.erase(qend, impl_->queue.end());
                                    auto cend = std::remove_if(
                                        impl_->chan_queue.begin(), impl_->chan_queue.end(),
                                        [&](const PendingChannelOp& o){
                                            return o.kind == PendingChannelOp::Kind::kInvite
                                                && o.peer == fetched_for;
                                        });
                                    inv_dropped = static_cast<std::size_t>(
                                        std::distance(cend, impl_->chan_queue.end()));
                                    impl_->chan_queue.erase(cend, impl_->chan_queue.end());
                                }
                                emit errorOccurred(QString(
                                    "no such user: '%1' is not registered on "
                                    "this server (or hasn't connected yet) — "
                                    "%2 message(s) and %3 invite(s) dropped")
                                    .arg(QString::fromStdString(fetched_for))
                                    .arg(dm_dropped).arg(inv_dropped));
                                // Mesh-bootstrap cleanup: if this failed
                                // fetch was a mesh-dial bootstrap, drop the
                                // pending dial state so we don't leak it.
                                auto bit = impl_->mesh_bootstrap_pending.find(fetched_for);
                                if (bit != impl_->mesh_bootstrap_pending.end()) {
                                    impl_->pending_mesh_dials.erase(bit->second);
                                    impl_->mesh_bootstrap_pending.erase(bit);
                                }
                                continue;
                            }
                            // Successful fetch: bind a session keyed by the
                            // username we asked for. The queue's front entry
                            // (DM or invite) will pick this session up on
                            // the next worker pass.
                            auto& sess = impl_->sessions[fetched_for];
                            std::memcpy(sess.peer_pub.data(),
                                        r.bundle().identity_pubkey().data(), 32);
                            std::memcpy(sess.peer_x.data(), r.bundle().signed_prekey().data(),
                                        32);
                            auto shared = derive_shared_secret(
                                impl_->x25519,
                                std::span<const std::uint8_t, 32>(sess.peer_x.data(), 32));
                            sess.rat.emplace(fb::crypto::DoubleRatchet::init_alice(
                                std::span<const std::uint8_t, 32>(shared.data(), shared.size()),
                                std::span<const std::uint8_t, 32>(sess.peer_x.data(), 32)));
                            sess.initialized_as_alice = true;
                            emit log(QString("ratchet ready for %1")
                                         .arg(QString::fromStdString(fetched_for)));
                            // Mesh-bootstrap step 3: if this fetch was for a
                            // mesh-dial we deferred, the session is now ready
                            // — retry start_call_to_pub on the main thread
                            // so the call actually fires. Without this the
                            // call slot in calls_by_peer never gets created
                            // even though the ratchet exists.
                            auto bit = impl_->mesh_bootstrap_pending.find(fetched_for);
                            if (bit != impl_->mesh_bootstrap_pending.end()) {
                                const std::string peer_pub_str = bit->second;
                                impl_->mesh_bootstrap_pending.erase(bit);
                                auto dit = impl_->pending_mesh_dials.find(peer_pub_str);
                                if (dit != impl_->pending_mesh_dials.end()) {
                                    std::array<std::uint8_t, 32> peer_pub_arr{};
                                    std::memcpy(peer_pub_arr.data(),
                                                peer_pub_str.data(), 32);
                                    QString label = dit->second.label;
                                    bool with_video = dit->second.with_video;
                                    std::string room_id = dit->second.room_id;
                                    impl_->pending_mesh_dials.erase(dit);
                                    emit log(QString("mesh-bootstrap: session ready, "
                                                      "retrying dial to %1").arg(label));
                                    QMetaObject::invokeMethod(this,
                                        [this, peer_pub_arr, label, with_video,
                                         room_id]() {
                                            start_call_to_pub(peer_pub_arr, label,
                                                              with_video, room_id);
                                        }, Qt::QueuedConnection);
                                }
                            }
                            // Notify so the queue is re-processed on the
                            // next loop iteration immediately.
                            impl_->cv.notify_all();
                        } else if (f.body_case() == fb::proto::Frame::kEnvelope) {
                            const auto& env = f.envelope();
                            if (env.sender_pubkey().size() != 32) continue;
                            const std::string sender_pub_bytes(env.sender_pubkey().begin(),
                                                                env.sender_pubkey().end());
                            // Channel envelope?
                            if (env.recipient_case() ==
                                fb::proto::Envelope::kChannelGroupId) {
                                const auto& gid = env.channel_group_id();
                                if (gid.size() != 32) continue;
                                auto nit = impl_->chan_id_to_name.find(
                                    std::string(gid.begin(), gid.end()));
                                if (nit == impl_->chan_id_to_name.end()) continue;
                                auto& cs = impl_->channels[nit->second];
                                // Lazy install: each new sender's distribution
                                // is the same blob we already have (Phase 1
                                // simplification — out-of-band file). Real
                                // sender-keys exchanges per-sender via DM.
                                try {
                                    cs.session->install_peer_distribution(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                sender_pub_bytes.data()),
                                            sender_pub_bytes.size()),
                                        std::span<const std::uint8_t>(cs.own_dist.data(),
                                                                       cs.own_dist.size()));
                                } catch (...) {
                                    // Already installed for this sender — fine.
                                }
                                // Verify Envelope.aad consistency: when
                                // present, it MUST equal envelope_id ‖
                                // u64_be(timestamp_ms). A relay rewriting
                                // either field without also rewriting aad
                                // breaks the inner tag; rewriting aad
                                // bytes would break the AEAD. Old senders
                                // (pre-aad-binding) leave it empty — we
                                // honour that for backwards compat.
                                std::vector<std::uint8_t> outer_aad(
                                    env.aad().begin(), env.aad().end());
                                if (!outer_aad.empty()) {
                                    auto expected = envelope_aad_bytes(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                env.envelope_id().data()),
                                            env.envelope_id().size()),
                                        env.timestamp_ms());
                                    if (outer_aad != expected) {
                                        emit log("envelope aad inconsistent "
                                                  "with envelope_id+timestamp "
                                                  "— possible tamper, dropping");
                                        continue;
                                    }
                                }
                                // Branch on per-channel cipher: MLS
                                // channels route through MlsGroup::
                                // application_decrypt; SenderKeys path
                                // unchanged. If the channel is marked
                                // MLS but our local mls is null (e.g.
                                // we haven't completed a Welcome yet,
                                // or restarted before serialize() was
                                // wired) we fall through to SenderKeys
                                // decrypt as a best-effort fallback.
                                std::optional<std::vector<std::uint8_t>> pt;
                                const bool use_mls =
                                    cs.crypto == fb::store::SqliteStore::ChannelCrypto::kMls
                                    && cs.mls;
                                if (use_mls) {
                                    pt = cs.mls->application_decrypt(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                env.ciphertext().data()),
                                            env.ciphertext().size()));
                                } else {
                                    pt = cs.session->decrypt(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                sender_pub_bytes.data()),
                                            sender_pub_bytes.size()),
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                env.ciphertext().data()),
                                            env.ciphertext().size()),
                                        std::span<const std::uint8_t>(
                                            outer_aad.data(), outer_aad.size()));
                                }
                                if (!pt) {
                                    emit log(QString("channel decrypt failed (%1)")
                                                 .arg(use_mls ? "MLS"
                                                              : "SenderKeys — likely "
                                                                "sent before we installed "
                                                                "dist for sender"));
                                    continue;
                                }
                                fb::crypto::PubKey peer_pub_arr{};
                                std::memcpy(peer_pub_arr.data(), sender_pub_bytes.data(), 32);
                                // Persist the advanced peer chain state so the
                                // chain key + next index survive restart.
                                persist_chan_session(nit->second, cs);
                                if (impl_->store) {
                                    const auto rx_ms = static_cast<std::uint64_t>(
                                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count());
                                    impl_->store->chan_append_inbox(
                                        std::span<const std::uint8_t>(cs.id.data(),
                                                                       cs.id.size()),
                                        std::span<const std::uint8_t>(peer_pub_arr.data(), 32),
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(pt->data()),
                                            pt->size()),
                                        rx_ms);
                                }
                                emit channelMessageReceived(
                                    QString::fromStdString(nit->second),
                                    QString::fromStdString(
                                        fb::crypto::Identity::fingerprint(peer_pub_arr)),
                                    QString::fromStdString(
                                        std::string(pt->begin(), pt->end())));
                                continue;
                            }
                            // (DM envelope path follows below — unchanged)
                            // Reuse an existing session for this peer if we
                            // have one — bob may have already created
                            // sessions["alice"] (init_alice) by sending a
                            // DM to alice, in which case all subsequent
                            // inbound from alice MUST decrypt through that
                            // same session. Spinning up a parallel
                            // sessions["peer:<alice_8>"] (init_bob) gives
                            // us two ratchets for one logical peer, the DH
                            // chains never line up, and every inbound
                            // decrypt fails.
                            std::array<std::uint8_t, 32> sender_pub_arr{};
                            std::memcpy(sender_pub_arr.data(),
                                        sender_pub_bytes.data(), 32);
                            std::string sname;
                            for (auto& [name, s] : impl_->sessions) {
                                if (s.rat && s.peer_pub == sender_pub_arr) {
                                    sname = name;
                                    break;
                                }
                            }
                            if (sname.empty()) {
                                // First-time peer — create a fresh init_bob
                                // session keyed by an opaque "peer:<8>" tag.
                                sname = "peer:" + sender_pub_bytes.substr(0, 8);
                            }
                            auto& sess = impl_->sessions[sname];
                            if (!sess.rat) {
                                std::array<std::uint8_t, 32> peer_x{};
                                if (crypto_sign_ed25519_pk_to_curve25519(
                                        peer_x.data(),
                                        reinterpret_cast<const std::uint8_t*>(
                                            sender_pub_bytes.data())) != 0) {
                                    continue;
                                }
                                auto shared = derive_shared_secret(
                                    impl_->x25519,
                                    std::span<const std::uint8_t, 32>(peer_x.data(), 32));
                                sess.rat.emplace(fb::crypto::DoubleRatchet::init_bob(
                                    std::span<const std::uint8_t, 32>(shared.data(),
                                                                       shared.size()),
                                    std::span<const std::uint8_t, 32>(impl_->x25519.priv.data(),
                                                                       32),
                                    std::span<const std::uint8_t, 32>(impl_->x25519.pub.data(),
                                                                       32)));
                                // Stash peer keys so the media_queue drain
                                // can find this session by peer_pub later.
                                std::memcpy(sess.peer_pub.data(),
                                            sender_pub_bytes.data(), 32);
                                sess.peer_x = peer_x;
                            }
                            // Same Envelope.aad consistency check as the
                            // channel path — see the channel_group_id
                            // branch above. Empty aad ⇒ pre-binding
                            // sender, treated as outer_aad=empty.
                            std::vector<std::uint8_t> outer_aad(
                                env.aad().begin(), env.aad().end());
                            if (!outer_aad.empty()) {
                                auto expected = envelope_aad_bytes(
                                    std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(
                                            env.envelope_id().data()),
                                        env.envelope_id().size()),
                                    env.timestamp_ms());
                                if (outer_aad != expected) {
                                    emit log("envelope aad inconsistent — "
                                              "possible tamper, dropping DM");
                                    continue;
                                }
                            }
                            auto pt = sess.rat->decrypt(
                                std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t*>(
                                        env.ciphertext().data()),
                                    env.ciphertext().size()),
                                std::span<const std::uint8_t>(
                                    outer_aad.data(), outer_aad.size()));
                            if (!pt) {
                                emit log("decrypt failed");
                                continue;
                            }
                            fb::crypto::PubKey peer_pub_arr{};
                            std::memcpy(peer_pub_arr.data(), sender_pub_bytes.data(), 32);
                            const QString peer_fp = QString::fromStdString(
                                fb::crypto::Identity::fingerprint(peer_pub_arr));

                            // Inner body is now a DmPayload — text or
                            // channel-key invite.
                            fb::proto::DmPayload payload;
                            if (!payload.ParseFromArray(pt->data(),
                                                        static_cast<int>(pt->size()))) {
                                emit log("DmPayload parse failed");
                                continue;
                            }
                            // Resolve sender's registered username from the
                            // local cache up front; if absent, kick off a
                            // server-side lookup so the UI rename arrives
                            // shortly. The cached name (if any) rides along
                            // on messageReceived so MainWindow can file the
                            // message under "dm:<username>" immediately and
                            // skip the fingerprint-shown-then-renamed dance.
                            QString cached_username;
                            if (impl_->store) {
                                auto cached = impl_->store->peer_name(
                                    std::span<const std::uint8_t>(peer_pub_arr.data(),
                                                                   peer_pub_arr.size()));
                                if (cached) {
                                    cached_username = QString::fromStdString(*cached);
                                } else {
                                    fb::proto::Frame qf;
                                    qf.mutable_username_lookup()->set_pubkey(
                                        std::string(env.sender_pubkey().begin(),
                                                    env.sender_pubkey().end()));
                                    blocking_send(impl_->conn, serialize(qf));
                                }
                            }
                            if (payload.body_case() == fb::proto::DmPayload::kText) {
                                const auto rx_ms = static_cast<std::uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
                                if (impl_->store) {
                                    std::vector<std::uint8_t> envid(env.envelope_id().begin(),
                                                                     env.envelope_id().end());
                                    std::vector<std::uint8_t> raw_text(payload.text().begin(),
                                                                        payload.text().end());
                                    impl_->store->append_inbox(
                                        std::span<const std::uint8_t>(envid.data(),
                                                                       envid.size()),
                                        std::span<const std::uint8_t>(peer_pub_arr.data(), 32),
                                        std::span<const std::uint8_t>(raw_text.data(),
                                                                       raw_text.size()),
                                        rx_ms);
                                }
                                emit messageReceived(
                                    peer_fp, cached_username,
                                    QString::fromStdString(payload.text()));
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kChannelKey) {
                                const auto& ck = payload.channel_key();
                                if (ck.channel_id().size() != 32) continue;
                                // Install the inviter's distribution into the
                                // channel session. Create the channel
                                // bookkeeping if needed.
                                std::array<std::uint8_t, 32> ch_id{};
                                std::memcpy(ch_id.data(), ck.channel_id().data(), 32);
                                auto& cs = impl_->channels[ck.channel_name()];
                                cs.id = ch_id;
                                impl_->chan_id_to_name[std::string(
                                    reinterpret_cast<const char*>(ch_id.data()),
                                    ch_id.size())] = ck.channel_name();
                                std::vector<std::uint8_t> dist_blob(
                                    ck.distribution().ByteSizeLong());
                                if (!ck.distribution().SerializeToArray(
                                        dist_blob.data(),
                                        static_cast<int>(dist_blob.size()))) {
                                    continue;
                                }
                                cs.own_dist = dist_blob;
                                try {
                                    cs.session->install_peer_distribution(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                sender_pub_bytes.data()),
                                            sender_pub_bytes.size()),
                                        std::span<const std::uint8_t>(dist_blob.data(),
                                                                       dist_blob.size()));
                                } catch (...) {}
                                if (!cs.subscribed) {
                                    fb::proto::Frame subf;
                                    subf.mutable_chan_subscribe()->set_channel_group_id(
                                        ck.channel_id());
                                    blocking_send(impl_->conn, serialize(subf));
                                    cs.subscribed = true;
                                }
                                // Persist the channel + its peer-dist + the
                                // session state so this channel is intact
                                // after a restart.
                                persist_chan_meta(ck.channel_name(), cs);
                                persist_chan_peer_dist(
                                    cs,
                                    std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(
                                            sender_pub_bytes.data()),
                                        sender_pub_bytes.size()),
                                    std::span<const std::uint8_t>(dist_blob.data(),
                                                                   dist_blob.size()));
                                persist_chan_session(ck.channel_name(), cs);
                                emit log(QString("invited to #%1 by %2")
                                             .arg(QString::fromStdString(ck.channel_name()))
                                             .arg(peer_fp));
                                emit channelJoined(
                                    QString::fromStdString(ck.channel_name()));
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kMlsInviteRequest) {
                                const auto& m = payload.mls_invite_request();
                                if (m.channel_id().size() != 32) continue;
                                const QByteArray cid_qb(
                                    m.channel_id().data(),
                                    static_cast<int>(m.channel_id().size()));
                                emit mlsInviteRequestReceived(
                                    peer_fp, cid_qb,
                                    QString::fromStdString(m.channel_name()));
                                emit log(QString("inbound MLS invite-request "
                                                  "for #%1 from %2 — auto-replying "
                                                  "with KeyPackage")
                                             .arg(QString::fromStdString(m.channel_name()))
                                             .arg(peer_fp));
                                // Joiner-side auto-orchestration: create a
                                // ChannelState entry (no MlsGroup yet —
                                // only Welcome materialises one) and
                                // generate a PendingMlsJoin. Send the KP
                                // back to the inviter via the same DM
                                // ratchet we just decoded the request on.
                                try {
                                    auto& cs = impl_->channels[m.channel_name()];
                                    if (cs.id[0] == 0 && cs.id[1] == 0) {
                                        std::memcpy(cs.id.data(),
                                                    m.channel_id().data(), 32);
                                        impl_->chan_id_to_name[std::string(
                                            m.channel_id().begin(),
                                            m.channel_id().end())] = m.channel_name();
                                    }
                                    cs.crypto =
                                        fb::store::SqliteStore::ChannelCrypto::kMls;
                                    if (!cs.pending_join) {
                                        cs.pending_join =
                                            fb::crypto::MlsGroup::start_join(
                                                std::span<const std::uint8_t, 32>(
                                                    impl_->identity->public_key().data(), 32));
                                    }
                                    auto kp = cs.pending_join->key_package();
                                    auto reply_payload = pack_mls_key_package_payload(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                m.channel_id().data()), 32),
                                        std::span<const std::uint8_t>(
                                            kp.data(), kp.size()));
                                    PendingSend ps;
                                    ps.peer = sname;
                                    ps.pre_packed_payload = std::move(reply_payload);
                                    {
                                        std::lock_guard lk(impl_->mu);
                                        impl_->queue.push_back(std::move(ps));
                                    }
                                    impl_->cv.notify_all();
                                } catch (const std::exception& e) {
                                    emit log(QString("MLS join-start failed: %1")
                                                 .arg(e.what()));
                                }
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kMlsKeyPackage) {
                                const auto& m = payload.mls_key_package();
                                if (m.channel_id().size() != 32) continue;
                                const QByteArray cid_qb(
                                    m.channel_id().data(),
                                    static_cast<int>(m.channel_id().size()));
                                emit mlsKeyPackageReceived(peer_fp, cid_qb,
                                    QByteArray(m.key_package().data(),
                                                static_cast<int>(m.key_package().size())));
                                emit log(QString("inbound MLS KeyPackage (%1B) "
                                                  "from %2 — calling add_member")
                                             .arg(static_cast<int>(m.key_package().size()))
                                             .arg(peer_fp));
                                // Inviter-side auto-orchestration: feed the
                                // KP into our MlsGroup via add_member,
                                // unwrap the Welcome and Commit. Send the
                                // Welcome back to the joiner; broadcast
                                // the Commit to every other existing
                                // member (skipped in v0 since we don't
                                // track per-channel membership beyond the
                                // immediate add).
                                std::string chan_name;
                                {
                                    auto nit = impl_->chan_id_to_name.find(
                                        std::string(m.channel_id().begin(),
                                                     m.channel_id().end()));
                                    if (nit != impl_->chan_id_to_name.end()) {
                                        chan_name = nit->second;
                                    }
                                }
                                if (chan_name.empty()) {
                                    emit log("MLS KP arrived for unknown channel — dropping");
                                    continue;
                                }
                                auto& cs = impl_->channels[chan_name];
                                if (!cs.mls) {
                                    emit log("MLS KP arrived but local MLS group "
                                              "not initialised — dropping");
                                    continue;
                                }
                                try {
                                    // Multi-member-correct add: propose,
                                    // broadcast the proposal to every
                                    // OTHER existing member, commit_
                                    // pending, then broadcast the
                                    // commit to those same existing
                                    // members and the welcome to the
                                    // joiner. The 1:1 inviter↔joiner
                                    // case degenerates to "no other
                                    // members" so the proposal/commit
                                    // broadcast loops just don't fire.
                                    auto kp_span = std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(
                                            m.key_package().data()),
                                        m.key_package().size());
                                    auto proposal_bytes =
                                        cs.mls->propose_add_member(kp_span);
                                    persist_mls_last_op(cs);
                                    // Snapshot existing members BEFORE
                                    // commit_pending advances the
                                    // roster — these are the peers we
                                    // need to send the proposal+commit
                                    // to. Excludes self and the about-
                                    // to-be-added joiner (whose pub is
                                    // not in the roster yet).
                                    std::vector<std::string> existing_others;
                                    {
                                        const auto& my_pub =
                                            impl_->identity->public_key();
                                        for (const auto& id :
                                             cs.mls->member_identities()) {
                                            if (id.size() != 32) continue;
                                            if (std::equal(my_pub.begin(),
                                                            my_pub.end(),
                                                            id.begin())) continue;
                                            existing_others.push_back(
                                                std::string(id.begin(), id.end()));
                                        }
                                    }
                                    // Find session names for each
                                    // existing-other peer pubkey, queue
                                    // the proposal payload to each.
                                    auto proposal_payload_template =
                                        pack_mls_proposal_payload(
                                            std::span<const std::uint8_t>(
                                                reinterpret_cast<const std::uint8_t*>(
                                                    m.channel_id().data()), 32),
                                            std::span<const std::uint8_t>(
                                                proposal_bytes.data(),
                                                proposal_bytes.size()));
                                    auto enqueue_to_pub =
                                        [&](const std::string& pub_str,
                                            const std::vector<std::uint8_t>& payload) {
                                        std::string sess_name;
                                        std::array<std::uint8_t, 32> pub_arr{};
                                        std::memcpy(pub_arr.data(),
                                                    pub_str.data(), 32);
                                        for (const auto& [name, ses] :
                                             impl_->sessions) {
                                            if (ses.rat &&
                                                ses.peer_pub == pub_arr) {
                                                sess_name = name;
                                                break;
                                            }
                                        }
                                        if (sess_name.empty()) return false;
                                        PendingSend qs;
                                        qs.peer = sess_name;
                                        qs.pre_packed_payload = payload;
                                        {
                                            std::lock_guard lk(impl_->mu);
                                            impl_->queue.push_back(std::move(qs));
                                        }
                                        impl_->cv.notify_all();
                                        return true;
                                    };
                                    for (const auto& pub_str : existing_others) {
                                        if (!enqueue_to_pub(pub_str,
                                                proposal_payload_template)) {
                                            emit log(QString(
                                                "MLS proposal: no DM session for "
                                                "existing member — they'll need "
                                                "a re-invite to catch up"));
                                        }
                                    }
                                    // Now commit and broadcast results.
                                    auto add = cs.mls->commit_pending();
                                    persist_mls_last_op(cs);
                                    auto welcome_payload = pack_mls_welcome_payload(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                m.channel_id().data()), 32),
                                        chan_name,
                                        std::span<const std::uint8_t>(
                                            add.welcome.data(), add.welcome.size()));
                                    {
                                        PendingSend ps;
                                        ps.peer = sname;
                                        ps.pre_packed_payload = std::move(welcome_payload);
                                        {
                                            std::lock_guard lk(impl_->mu);
                                            impl_->queue.push_back(std::move(ps));
                                        }
                                        impl_->cv.notify_all();
                                    }
                                    emit log(QString("MLS Welcome (%1B) queued "
                                                      "for %2")
                                                 .arg(static_cast<int>(add.welcome.size()))
                                                 .arg(peer_fp));
                                    auto commit_payload =
                                        pack_mls_commit_payload(
                                            std::span<const std::uint8_t>(
                                                reinterpret_cast<const std::uint8_t*>(
                                                    m.channel_id().data()), 32),
                                            std::span<const std::uint8_t>(
                                                add.commit.data(),
                                                add.commit.size()));
                                    int fanned = 0;
                                    for (const auto& pub_str : existing_others) {
                                        if (enqueue_to_pub(pub_str,
                                                commit_payload)) ++fanned;
                                    }
                                    if (fanned > 0) {
                                        emit log(QString("MLS Commit broadcast to "
                                                          "%1 existing member(s)")
                                                     .arg(fanned));
                                    }
                                    // Refresh our cached membership view.
                                    cs.mls_member_pubs.clear();
                                    {
                                        const auto& my_pub =
                                            impl_->identity->public_key();
                                        for (const auto& id :
                                             cs.mls->member_identities()) {
                                            if (id.size() != 32) continue;
                                            if (std::equal(my_pub.begin(),
                                                            my_pub.end(),
                                                            id.begin())) continue;
                                            cs.mls_member_pubs.insert(
                                                std::string(id.begin(), id.end()));
                                        }
                                    }
                                } catch (const std::exception& e) {
                                    emit log(QString("MLS add_member failed: %1")
                                                 .arg(e.what()));
                                }
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kMlsWelcome) {
                                const auto& m = payload.mls_welcome();
                                if (m.channel_id().size() != 32) continue;
                                const QByteArray cid_qb(
                                    m.channel_id().data(),
                                    static_cast<int>(m.channel_id().size()));
                                emit mlsWelcomeReceived(peer_fp, cid_qb,
                                    QString::fromStdString(m.channel_name()),
                                    QByteArray(m.welcome().data(),
                                                static_cast<int>(m.welcome().size())));
                                emit log(QString("inbound MLS Welcome for #%1 "
                                                  "from %2 — completing pending join")
                                             .arg(QString::fromStdString(m.channel_name()))
                                             .arg(peer_fp));
                                // Joiner-side auto-orchestration: complete
                                // our PendingMlsJoin → hydrated MlsGroup.
                                auto& cs = impl_->channels[m.channel_name()];
                                if (!cs.pending_join) {
                                    emit log("MLS Welcome arrived without a pending join "
                                              "— ignoring (re-issue an InviteRequest "
                                              "to restart)");
                                    continue;
                                }
                                try {
                                    cs.mls = cs.pending_join->complete(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                m.welcome().data()),
                                            m.welcome().size()));
                                    cs.pending_join.reset();
                                    cs.crypto =
                                        fb::store::SqliteStore::ChannelCrypto::kMls;
                                    // Persist the JOINER seed: the
                                    // bootstrap that includes
                                    // sig_priv + leaf_priv + init_priv
                                    // + KeyPackage + Welcome bytes.
                                    // No ops to log yet — the joiner
                                    // starts at the post-Welcome
                                    // state.
                                    persist_mls_seed(cs);
                                    // Subscribe to the channel envelope
                                    // fan-out so future application
                                    // messages reach us.
                                    if (!cs.subscribed) {
                                        fb::proto::Frame subf;
                                        subf.mutable_chan_subscribe()->set_channel_group_id(
                                            m.channel_id());
                                        blocking_send(impl_->conn, serialize(subf));
                                        cs.subscribed = true;
                                    }
                                    impl_->chan_id_to_name[std::string(
                                        m.channel_id().begin(),
                                        m.channel_id().end())] = m.channel_name();
                                    emit channelJoined(QString::fromStdString(
                                        m.channel_name()));
                                    // Populate membership cache so any
                                    // future add we initiate fans out
                                    // to the right peers.
                                    const auto& my_pub =
                                        impl_->identity->public_key();
                                    for (const auto& id :
                                         cs.mls->member_identities()) {
                                        if (id.size() != 32) continue;
                                        if (std::equal(my_pub.begin(),
                                                        my_pub.end(),
                                                        id.begin())) continue;
                                        cs.mls_member_pubs.insert(
                                            std::string(id.begin(), id.end()));
                                    }
                                    emit log(QString("MLS group hydrated for #%1 "
                                                      "(member_count=%2)")
                                                 .arg(QString::fromStdString(m.channel_name()))
                                                 .arg(cs.mls->member_count()));
                                } catch (const std::exception& e) {
                                    emit log(QString("MLS complete failed: %1")
                                                 .arg(e.what()));
                                }
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kMlsCommit) {
                                const auto& m = payload.mls_commit();
                                if (m.channel_id().size() != 32) continue;
                                const QByteArray cid_qb(
                                    m.channel_id().data(),
                                    static_cast<int>(m.channel_id().size()));
                                emit mlsCommitReceived(peer_fp, cid_qb,
                                    QByteArray(m.commit().data(),
                                                static_cast<int>(m.commit().size())));
                                emit log(QString("inbound MLS Commit (%1B) "
                                                  "from %2 — applying")
                                             .arg(static_cast<int>(m.commit().size()))
                                             .arg(peer_fp));
                                std::string chan_name;
                                {
                                    auto nit = impl_->chan_id_to_name.find(
                                        std::string(m.channel_id().begin(),
                                                     m.channel_id().end()));
                                    if (nit != impl_->chan_id_to_name.end())
                                        chan_name = nit->second;
                                }
                                if (chan_name.empty()) continue;
                                auto& cs = impl_->channels[chan_name];
                                if (!cs.mls) continue;
                                try {
                                    cs.mls->apply_commit(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                m.commit().data()),
                                            m.commit().size()));
                                    persist_mls_last_op(cs);
                                    // Refresh membership cache after the
                                    // commit advances the roster.
                                    cs.mls_member_pubs.clear();
                                    const auto& my_pub =
                                        impl_->identity->public_key();
                                    for (const auto& id :
                                         cs.mls->member_identities()) {
                                        if (id.size() != 32) continue;
                                        if (std::equal(my_pub.begin(),
                                                        my_pub.end(),
                                                        id.begin())) continue;
                                        cs.mls_member_pubs.insert(
                                            std::string(id.begin(), id.end()));
                                    }
                                } catch (const std::exception& e) {
                                    emit log(QString("MLS apply_commit failed: %1")
                                                 .arg(e.what()));
                                }
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kMlsProposal) {
                                const auto& m = payload.mls_proposal();
                                if (m.channel_id().size() != 32) continue;
                                emit log(QString("inbound MLS Proposal (%1B) "
                                                  "from %2 — staging")
                                             .arg(static_cast<int>(m.proposal().size()))
                                             .arg(peer_fp));
                                std::string chan_name;
                                {
                                    auto nit = impl_->chan_id_to_name.find(
                                        std::string(m.channel_id().begin(),
                                                     m.channel_id().end()));
                                    if (nit != impl_->chan_id_to_name.end())
                                        chan_name = nit->second;
                                }
                                if (chan_name.empty()) continue;
                                auto& cs = impl_->channels[chan_name];
                                if (!cs.mls) continue;
                                try {
                                    cs.mls->handle_proposal(
                                        std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t*>(
                                                m.proposal().data()),
                                            m.proposal().size()));
                                    persist_mls_last_op(cs);
                                } catch (const std::exception& e) {
                                    emit log(QString("MLS handle_proposal "
                                                      "failed: %1").arg(e.what()));
                                }
                            } else if (payload.body_case() ==
                                       fb::proto::DmPayload::kMediaSignal) {
                                const auto& ms = payload.media_signal();
                                if (ms.call_id().size() != 16) continue;
                                std::array<std::uint8_t, 32> peer_pub{};
                                std::memcpy(peer_pub.data(), sender_pub_bytes.data(), 32);
                                QByteArray sig_payload(ms.payload().data(),
                                                        static_cast<int>(ms.payload().size()));
                                const auto kind =
                                    static_cast<MediaCall::SignalKind>(ms.kind());
                                // Diagnostic: trace every inbound media signal
                                // so call-failure logs show which step the
                                // peer-to-peer signaling stops at.
                                {
                                    static const char* names[] = {
                                        "(0)", "OFFER", "ANSWER", "ICE", "HANGUP", "SFRAME_KEY"
                                    };
                                    const int k = static_cast<int>(kind);
                                    const char* label = (k >= 0 && k < 6) ? names[k] : "?";
                                    emit log(QString("inbound media signal: %1 (%2 bytes)")
                                                 .arg(label)
                                                 .arg(static_cast<int>(sig_payload.size())));
                                }

                                // Marshal the inbound dispatch onto the Qt
                                // main thread — MediaCall lives there.
                                QMetaObject::invokeMethod(this,
                                    [this, peer_pub, kind, sig_payload, ms_call_id =
                                     std::array<std::uint8_t, 16>([&]{
                                        std::array<std::uint8_t, 16> a{};
                                        std::memcpy(a.data(), ms.call_id().data(), 16);
                                        return a;
                                     }())]() {
                                        // Multi-call dispatch: every call is
                                        // keyed by peer pubkey in calls_by_peer.
                                        // For 1:1 the map has one entry; for
                                        // mesh channel calls there's one per
                                        // peer in the room.
                                        const std::string peer_key(
                                            reinterpret_cast<const char*>(peer_pub.data()),
                                            peer_pub.size());
                                        if (kind == MediaCall::SignalKind::kOffer) {
                                            // Glare at the per-peer level only:
                                            // we already have a call going with
                                            // THIS peer. Ignore — both ends
                                            // would otherwise race two
                                            // PeerConnections to the same
                                            // partner.
                                            if (impl_->calls_by_peer.count(peer_key)) {
                                                emit log("inbound OFFER ignored — "
                                                          "already have an active call "
                                                          "with this peer");
                                                return;
                                            }
                                            auto* call = new MediaCall(this);
                                            Impl::CallEntry entry;
                                            entry.call    = call;
                                            entry.call_id = ms_call_id;
                                            impl_->calls_by_peer[peer_key] = entry;
                                            const QString label = peer_label_for(
                                                std::span<const std::uint8_t>(
                                                    peer_pub.data(), peer_pub.size()));
                                            // Capture peer_pub + ms_call_id BY
                                            // VALUE in the sendSignal lambda so
                                            // each call's outbound signaling
                                            // routes back to the right peer
                                            // even when there are several
                                            // simultaneous calls.
                                            QObject::connect(call, &MediaCall::sendSignal, this,
                                                [this, peer_pub, ms_call_id](
                                                    int kind_, const QByteArray& bytes) {
                                                    PendingMediaSignal pms;
                                                    pms.peer_pub = peer_pub;
                                                    pms.call_id  = ms_call_id;
                                                    pms.kind     = static_cast<std::uint32_t>(kind_);
                                                    pms.payload.assign(
                                                        bytes.constBegin(), bytes.constEnd());
                                                    {
                                                        std::lock_guard lk(impl_->mu);
                                                        impl_->media_queue.push_back(std::move(pms));
                                                    }
                                                    impl_->cv.notify_all();
                                                });
                                            QObject::connect(call, &MediaCall::stateChanged, this,
                                                [this, label, peer_key](MediaCall::State s) {
                                                    emit callStateChanged(label, static_cast<int>(s));
                                                    if (s == MediaCall::State::kClosed) {
                                                        auto it = impl_->calls_by_peer.find(peer_key);
                                                        if (it != impl_->calls_by_peer.end()) {
                                                            it->second.call->deleteLater();
                                                            impl_->calls_by_peer.erase(it);
                                                        }
                                                        // Drop any room-mesh
                                                        // tracking for this peer
                                                        // so a re-join correctly
                                                        // re-dials.
                                                        for (auto& [rid, peers] :
                                                             impl_->room_mesh_peers) {
                                                            peers.erase(peer_key);
                                                        }
                                                    }
                                                });
                                            QObject::connect(call, &MediaCall::log, this,
                                                [this](const QString& m) { emit log("[call] " + m); });
                                            QObject::connect(call, &MediaCall::remoteVideoFrame,
                                                this, &ChatClient::remoteVideoFrame);
                                            // SFrame: derive base key from X3DH(shared, peer_x25519).
                                            std::array<std::uint8_t, 32> peer_x{};
                                            if (crypto_sign_ed25519_pk_to_curve25519(
                                                    peer_x.data(), peer_pub.data()) == 0) {
                                                const auto shared = derive_shared_secret(
                                                    impl_->x25519,
                                                    std::span<const std::uint8_t, 32>(peer_x.data(), 32));
                                                call->set_sframe_context(shared, ms_call_id);
                                            }
                                            call->receive_offer(sig_payload);
                                            // Mesh-call auto-accept: if this
                                            // peer is in a room we've joined,
                                            // the user already opted in by
                                            // clicking Voice on that channel
                                            // — popping a per-peer Accept
                                            // modal for every other roster
                                            // member would be hostile UX.
                                            // Tag the entry with the matching
                                            // room_id and accept immediately.
                                            std::string matched_room;
                                            for (const auto& [rid, peers] :
                                                 impl_->room_mesh_peers) {
                                                if (peers.count(peer_key)) {
                                                    matched_room = rid;
                                                    break;
                                                }
                                            }
                                            if (!matched_room.empty()) {
                                                impl_->calls_by_peer[peer_key]
                                                    .room_id = matched_room;
                                                emit log("auto-accepting mesh "
                                                          "OFFER (peer in active "
                                                          "channel call)");
                                                call->accept_incoming(
                                                    /*with_video=*/false);
                                                if (impl_->self_muted) {
                                                    call->set_self_muted(true);
                                                }
                                                return;
                                            }
                                            // 1:1 DM call — surface the modal
                                            // for explicit accept/decline.
                                            fb::crypto::PubKey arr{};
                                            std::memcpy(arr.data(), peer_pub.data(), 32);
                                            emit incomingCall(label,
                                                QString::fromStdString(
                                                    fb::crypto::Identity::fingerprint(arr)));
                                            return;
                                        }
                                        // Non-OFFER signals: dispatch to the
                                        // matching call (if any).
                                        auto it = impl_->calls_by_peer.find(peer_key);
                                        if (it == impl_->calls_by_peer.end()) {
                                            emit log("inbound media signal ignored — "
                                                      "no active call for this peer");
                                            return;
                                        }
                                        MediaCall* call = it->second.call;
                                        switch (kind) {
                                            case MediaCall::SignalKind::kAnswer:
                                                call->receive_answer(sig_payload);
                                                break;
                                            case MediaCall::SignalKind::kIce:
                                                call->receive_ice(sig_payload);
                                                break;
                                            case MediaCall::SignalKind::kHangup:
                                                call->hangup(/*silent=*/true);
                                                break;
                                            default: break;
                                        }
                                    },
                                    Qt::QueuedConnection);
                            }
                        }
                    }
                }
            }
                }   // end of new outer block opened by W2 patch
        } catch (const std::exception& e) {
            emit errorOccurred(QString::fromStdString(e.what()));
        }
        impl_->running = false;
    });
}

void ChatClient::send_to_peer(const QString& peer, const QString& text) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->queue.push_back({peer.toStdString(), text.toStdString(), {}});
    }
    impl_->cv.notify_all();
}

void ChatClient::create_channel(const QString& name, const QString& dist_file_path) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kCreate, name.toStdString(),
                                      dist_file_path.toStdString(), {}, {}});
    }
    impl_->cv.notify_all();
}

void ChatClient::join_channel(const QString& name, const QString& dist_file_path) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kJoin, name.toStdString(),
                                      dist_file_path.toStdString(), {}, {}});
    }
    impl_->cv.notify_all();
}

void ChatClient::send_to_channel(const QString& name, const QString& text) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kSend, name.toStdString(),
                                      {}, text.toStdString(), {}});
    }
    impl_->cv.notify_all();
}

void ChatClient::create_local_channel(const QString& name, bool use_mls) {
    {
        std::lock_guard lk(impl_->mu);
        PendingChannelOp op;
        op.kind         = PendingChannelOp::Kind::kCreateLocal;
        op.channel_name = name.toStdString();
        op.use_mls      = use_mls;
        impl_->chan_queue.push_back(std::move(op));
    }
    impl_->cv.notify_all();
}

void ChatClient::invite_peer_to_channel(const QString& channel_name, const QString& peer) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kInvite,
                                      channel_name.toStdString(), {}, {},
                                      peer.toStdString()});
    }
    impl_->cv.notify_all();
}

void ChatClient::join_channel_call(const QString& channel_name, bool with_video) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kRoomJoin,
                                      channel_name.toStdString(), {}, {}, {},
                                      with_video});
    }
    impl_->cv.notify_all();
}

void ChatClient::invite_peer_to_mls_channel(const QString& channel_name,
                                              const QString& peer) {
    const auto cid = channel_id_from_name(channel_name.toStdString());
    QByteArray cid_qb(reinterpret_cast<const char*>(cid.data()),
                      static_cast<int>(cid.size()));
    send_mls_invite_request(peer, cid_qb, channel_name);
}

// ----- MLS handshake send helpers ------------------------------------
// Each builds a DmPayload of the matching variant, serializes it, and
// pushes a pre-packed PendingSend onto the same queue as text DMs so
// the worker encrypts + sends with the existing pairwise ratchet
// (no parallel queue / no second crypto path).
void ChatClient::send_mls_invite_request(const QString& peer,
                                          const QByteArray& channel_id,
                                          const QString& channel_name) {
    auto payload = pack_mls_invite_request_payload(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(channel_id.constData()),
            static_cast<std::size_t>(channel_id.size())),
        channel_name.toStdString());
    PendingSend ps;
    ps.peer = peer.toStdString();
    ps.pre_packed_payload = std::move(payload);
    {
        std::lock_guard lk(impl_->mu);
        impl_->queue.push_back(std::move(ps));
    }
    impl_->cv.notify_all();
}

void ChatClient::send_mls_key_package(const QString& peer,
                                       const QByteArray& channel_id,
                                       const QByteArray& key_package) {
    auto payload = pack_mls_key_package_payload(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(channel_id.constData()),
            static_cast<std::size_t>(channel_id.size())),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(key_package.constData()),
            static_cast<std::size_t>(key_package.size())));
    PendingSend ps;
    ps.peer = peer.toStdString();
    ps.pre_packed_payload = std::move(payload);
    {
        std::lock_guard lk(impl_->mu);
        impl_->queue.push_back(std::move(ps));
    }
    impl_->cv.notify_all();
}

void ChatClient::send_mls_welcome(const QString& peer,
                                   const QByteArray& channel_id,
                                   const QString& channel_name,
                                   const QByteArray& welcome) {
    auto payload = pack_mls_welcome_payload(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(channel_id.constData()),
            static_cast<std::size_t>(channel_id.size())),
        channel_name.toStdString(),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(welcome.constData()),
            static_cast<std::size_t>(welcome.size())));
    PendingSend ps;
    ps.peer = peer.toStdString();
    ps.pre_packed_payload = std::move(payload);
    {
        std::lock_guard lk(impl_->mu);
        impl_->queue.push_back(std::move(ps));
    }
    impl_->cv.notify_all();
}

void ChatClient::send_mls_commit(const QString& peer,
                                  const QByteArray& channel_id,
                                  const QByteArray& commit) {
    auto payload = pack_mls_commit_payload(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(channel_id.constData()),
            static_cast<std::size_t>(channel_id.size())),
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(commit.constData()),
            static_cast<std::size_t>(commit.size())));
    PendingSend ps;
    ps.peer = peer.toStdString();
    ps.pre_packed_payload = std::move(payload);
    {
        std::lock_guard lk(impl_->mu);
        impl_->queue.push_back(std::move(ps));
    }
    impl_->cv.notify_all();
}

void ChatClient::leave_channel_call(const QString& channel_name) {
    // Tear down every mesh MediaCall in this room before we tell the
    // server we've left — otherwise their pipelines linger as the user's
    // RTP keeps flowing toward peers who'll never hear it again.
    const auto chan_id = channel_id_from_name(channel_name.toStdString());
    const std::string room_id_str(
        reinterpret_cast<const char*>(chan_id.data()), chan_id.size());
    std::vector<MediaCall*> to_hangup;
    for (auto& [_, entry] : impl_->calls_by_peer) {
        if (entry.room_id == room_id_str && entry.call) {
            to_hangup.push_back(entry.call);
        }
    }
    for (MediaCall* call : to_hangup) {
        call->hangup();   // already on the Qt main thread (this method is
                          // invoked from the UI hangup button)
    }
    impl_->room_mesh_peers.erase(room_id_str);

    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kRoomLeave,
                                      channel_name.toStdString(), {}, {}, {},
                                      false});
    }
    impl_->cv.notify_all();
}

void ChatClient::set_self_muted(bool muted) {
    impl_->self_muted = muted;
    for (auto& [_, entry] : impl_->calls_by_peer) {
        if (entry.call) entry.call->set_self_muted(muted);
    }
}

bool ChatClient::self_muted() const { return impl_->self_muted; }

void ChatClient::leave_channel(const QString& channel_name) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->chan_queue.push_back({PendingChannelOp::Kind::kLeave,
                                      channel_name.toStdString(), {}, {}, {}});
    }
    impl_->cv.notify_all();
}

void ChatClient::disconnect() {
    // Tear down every active call before we shut the worker down — without
    // this, GStreamer pipelines outlive their owning ChatClient and the
    // process can exit with stranded webrtcbin instances.
    for (auto& [_, entry] : impl_->calls_by_peer) {
        if (entry.call) entry.call->hangup();
    }
    impl_->calls_by_peer.clear();
    impl_->room_mesh_peers.clear();
    impl_->running = false;
    impl_->cv.notify_all();
    if (impl_->worker.joinable()) impl_->worker.join();
}

// =============================================================================
// Voice / video calls — public surface.
//
// All MediaCall state lives on the Qt main thread (the same one that owns
// `this`). The worker thread only ever observes it via the media_queue
// (outbound signals) and via QMetaObject::invokeMethod for inbound signals.
//
// Multiple concurrent calls are supported: calls_by_peer maps a peer
// pubkey to a CallEntry. 1:1 DM calls produce one entry. Mesh channel
// calls produce N-1 entries, one per other participant in the room.
// =============================================================================

bool ChatClient::start_call_to_pub(const std::array<std::uint8_t, 32>& peer_pub_arr,
                                    const QString& display_label,
                                    bool with_video,
                                    const std::string& room_id) {
    const std::string peer_key(
        reinterpret_cast<const char*>(peer_pub_arr.data()), peer_pub_arr.size());
    if (impl_->calls_by_peer.count(peer_key)) {
        return false;   // already calling this peer
    }
    // Verify a ratchet session for this peer exists — without one the
    // worker's media-queue drain has nothing to encrypt outbound media
    // signals against and they get silently dropped. Lazy session
    // bootstrap (username_lookup → key_fetch → init_alice on first
    // mesh-dial) is a planned follow-up; for now require the user to
    // have exchanged at least one DM with the peer, which is the common
    // case if they're already in a shared channel.
    bool have_session = false;
    for (const auto& [_, s] : impl_->sessions) {
        if (s.rat && s.peer_pub == peer_pub_arr) { have_session = true; break; }
    }
    if (!have_session) {
        emit log(QString("start_call_to_pub: skipping %1 — no ratchet session "
                          "(send a DM first to bootstrap; lazy auto-bootstrap "
                          "is on the roadmap)").arg(display_label));
        return false;
    }
    auto* call = new MediaCall(this);
    Impl::CallEntry entry;
    entry.call    = call;
    entry.room_id = room_id;
    randombytes_buf(entry.call_id.data(), entry.call_id.size());
    const std::array<std::uint8_t, 16> call_id_arr = entry.call_id;
    impl_->calls_by_peer[peer_key] = entry;
    const QString label = display_label;

    // Derive the SFrame base key from the X3DH-shared secret + the fresh
    // call_id and hand it to MediaCall before start_outgoing — this turns
    // on the encoded-frame seal/open probes around opusenc / vp8enc /
    // rtpopusdepay / rtpvp8depay so an SFU (when one lands) can't read
    // frames. Wire-compatible with media_call.js on the web client.
    {
        std::array<std::uint8_t, 32> peer_x{};
        if (crypto_sign_ed25519_pk_to_curve25519(
                peer_x.data(), peer_pub_arr.data()) == 0) {
            const auto shared = derive_shared_secret(
                impl_->x25519,
                std::span<const std::uint8_t, 32>(peer_x.data(), 32));
            call->set_sframe_context(shared, call_id_arr);
        }
    }

    // Outbound signals: MediaCall asks us to deliver bytes to the peer
    // wrapped in DmPayload.media_signal. Push onto the worker's media
    // queue. peer_pub + call_id captured by VALUE so each MediaCall's
    // signaling routes to the right peer even with N concurrent calls.
    QObject::connect(call, &MediaCall::sendSignal, this,
        [this, peer_pub_arr, call_id_arr](int kind, const QByteArray& bytes) {
            PendingMediaSignal pms;
            pms.peer_pub = peer_pub_arr;
            pms.call_id  = call_id_arr;
            pms.kind     = static_cast<std::uint32_t>(kind);
            pms.payload.assign(bytes.constBegin(), bytes.constEnd());
            {
                std::lock_guard lk(impl_->mu);
                impl_->media_queue.push_back(std::move(pms));
            }
            impl_->cv.notify_all();
        });
    QObject::connect(call, &MediaCall::stateChanged, this,
        [this, label, peer_key](MediaCall::State s) {
            emit callStateChanged(label, static_cast<int>(s));
            if (s == MediaCall::State::kClosed) {
                auto it = impl_->calls_by_peer.find(peer_key);
                if (it != impl_->calls_by_peer.end()) {
                    it->second.call->deleteLater();
                    impl_->calls_by_peer.erase(it);
                }
                for (auto& [rid, peers] : impl_->room_mesh_peers) {
                    peers.erase(peer_key);
                }
            }
        });
    QObject::connect(call, &MediaCall::log, this,
        [this](const QString& m) { emit log("[call] " + m); });
    QObject::connect(call, &MediaCall::remoteVideoFrame, this,
        &ChatClient::remoteVideoFrame);

    call->start_outgoing(peer_pub_arr, with_video);
    // Newly-built pipeline starts un-muted; honour the per-client toggle
    // so a user who muted before joining a channel call stays silent on
    // the new mesh leg too.
    if (impl_->self_muted) call->set_self_muted(true);
    return true;
}

void ChatClient::start_call(const QString& peer_username, bool with_video) {
    auto sit = impl_->sessions.find(peer_username.toStdString());
    if (sit == impl_->sessions.end() || !sit->second.rat) {
        emit log(QString("start_call: no ratchet session for %1 — send a DM first to bootstrap")
                     .arg(peer_username));
        return;
    }
    if (!start_call_to_pub(sit->second.peer_pub, peer_username, with_video, /*room_id=*/{})) {
        emit log(QString("start_call: a call to %1 is already in progress")
                     .arg(peer_username));
    }
}

// Accept the most recently rung incoming call. v0 surfaces just one
// modal at a time; if multiple calls happen to be ringing simultaneously
// (rare — would require two parallel inbound OFFERs in the same window)
// the first one we find is accepted. Caller can hang up to advance.
void ChatClient::accept_call(bool with_video) {
    for (auto& [_, entry] : impl_->calls_by_peer) {
        if (entry.call && entry.call->state() == MediaCall::State::kRinging) {
            entry.call->accept_incoming(with_video);
            return;
        }
    }
}

void ChatClient::decline_call() {
    for (auto& [_, entry] : impl_->calls_by_peer) {
        if (entry.call && entry.call->state() == MediaCall::State::kRinging) {
            entry.call->hangup();
            return;
        }
    }
}

void ChatClient::hangup_call() {
    // 1:1 hangup: tear down every call that's NOT part of a room mesh.
    // Room calls are torn down via leave_channel_call instead so the
    // user can leave a single room without nuking unrelated DMs.
    for (auto& [_, entry] : impl_->calls_by_peer) {
        if (entry.call && entry.room_id.empty()) entry.call->hangup();
    }
}

std::vector<ChatClient::ChannelHistoryEntry> ChatClient::load_recent_channel_history(
    const QString& channel_name, std::size_t limit) {
    std::vector<ChannelHistoryEntry> out;
    if (!impl_->store) return out;
    auto cit = impl_->channels.find(channel_name.toStdString());
    if (cit == impl_->channels.end()) return out;
    const auto& cs = cit->second;
    auto rows = impl_->store->chan_recent_inbox(
        std::span<const std::uint8_t>(cs.id.data(), cs.id.size()), limit);
    out.reserve(rows.size());
    // Reverse so oldest-first.
    for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
        ChannelHistoryEntry e;
        e.text = QString::fromStdString(std::string(it->plaintext.begin(),
                                                     it->plaintext.end()));
        e.timestamp_ms = static_cast<std::int64_t>(it->timestamp_ms);
        if (it->sender_pub.size() == 32) {
            fb::crypto::PubKey k{};
            std::memcpy(k.data(), it->sender_pub.data(), 32);
            e.sender_fingerprint =
                QString::fromStdString(fb::crypto::Identity::fingerprint(k));
            e.is_self = impl_->identity &&
                        std::equal(it->sender_pub.begin(), it->sender_pub.end(),
                                   impl_->identity->public_key().begin());
        }
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<ChatClient::CachedPeer> ChatClient::cached_dm_peers() {
    std::vector<CachedPeer> out;
    if (!impl_->store) return out;
    for (const auto& p : impl_->store->all_cached_peers()) {
        out.push_back({QString::fromStdString(p.username)});
    }
    return out;
}

std::vector<ChatClient::HistoryEntry> ChatClient::load_recent_history(std::size_t limit) {
    std::vector<HistoryEntry> out;
    if (!impl_->store) return out;
    // Pull the most-recent `limit` rows from BOTH directions and merge by
    // timestamp. Earlier we only loaded inbox, so a logged-back-in user saw
    // only messages they had received — every reply they had sent was
    // silently missing on reconnect.
    auto inbox = impl_->store->recent_inbox(limit);
    auto outbox = impl_->store->recent_outbox(limit);
    out.reserve(inbox.size() + outbox.size());

    auto build = [&](const auto& r, bool outgoing) {
        HistoryEntry e;
        e.outgoing = outgoing;
        e.text = QString::fromStdString(std::string(r.plaintext.begin(), r.plaintext.end()));
        e.timestamp_ms = static_cast<std::int64_t>(r.timestamp_ms);
        if (r.peer_pub.size() == 32) {
            fb::crypto::PubKey k{};
            std::memcpy(k.data(), r.peer_pub.data(), 32);
            e.peer_fingerprint = QString::fromStdString(fb::crypto::Identity::fingerprint(k));
            auto cached = impl_->store->peer_name(
                std::span<const std::uint8_t>(r.peer_pub.data(), r.peer_pub.size()));
            if (cached) e.peer_username = QString::fromStdString(*cached);
        }
        return e;
    };
    for (const auto& r : inbox)  out.push_back(build(r, /*outgoing=*/false));
    for (const auto& r : outbox) out.push_back(build(r, /*outgoing=*/true));
    // Sort newest-first so the caller can reverse-iterate to render
    // oldest-first into the message buffer.
    std::sort(out.begin(), out.end(),
              [](const HistoryEntry& a, const HistoryEntry& b) {
                  return a.timestamp_ms > b.timestamp_ms;
              });
    if (out.size() > limit) out.resize(limit);
    return out;
}

}  // namespace fb::desktop
