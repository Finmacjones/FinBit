// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// fb-cli — proof-of-life Phase 0 client.
//
// Two modes:
//   send :  register identity, fetch peer's prekey bundle, derive a shared
//           secret via X25519 + HKDF, init the Double Ratchet as Alice,
//           encrypt one message, send the Envelope through the relay, exit.
//   listen: register identity, upload a prekey bundle, wait for envelopes,
//           lazily init Double Ratchet as Bob on first inbound message,
//           decrypt + print, loop.
//
// This is a Phase 0 simplification of X3DH:
//   - identity = Ed25519 long-term keypair
//   - "signed prekey" = X25519 keypair derived from the identity seed
//     (per-process for simplicity; production uses a separately-rotated SPK)
//   - shared_secret = HKDF-SHA256(X25519(my_x_priv, peer_x_pub),
//                                  info="FinBit-X3DH-v0", 32)
// Caller drives the role (--send vs --listen) so an end-to-end test can
// orchestrate a deterministic conversation.
// =============================================================================

#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <optional>
#include <random>
#include <sodium.h>
#include <span>
#include <string>
#include <vector>

#include "dm_payload.pb.h"
#include "envelope.pb.h"
#include "fb/config/build_config.hpp"
#include "fb/crypto/hkdf.hpp"
#include "fb/crypto/identity.hpp"
#include "fb/crypto/ratchet.hpp"
#include "fb/crypto/sender_keys.hpp"
#include "fb/net/frame_codec.hpp"
#include "fb/net/tcp.hpp"
#include "fb/p2p/gossip.hpp"
#include "handshake.pb.h"
#include "sender_keys.pb.h"

#include <fstream>

namespace {

constexpr std::string_view kX3dhInfo = "FinBit-X3DH-v0";

std::atomic_bool g_run{true};
void on_signal(int) { g_run = false; }

struct Args {
    std::string user;
    std::string peer;
    std::string text;
    std::string server_host = "127.0.0.1";
    std::uint16_t server_port = 8765;
    bool listen = false;
    bool send = false;
    int wait_ms = 5000;
    // Channel mode (Phase 1):
    std::string channel_name;       // hashed to 32-byte channel id
    std::string dist_file;          // where the distribution blob lives
    bool channel_create = false;    // create chain + write dist + send + linger
    bool channel_listen = false;    // read dist + subscribe + listen
    bool channel_invite = false;    // create chain + DM-deliver dist to peer + send
    int linger_ms = 1500;           // for channel-create: how long to stay after send
    // P2P mode (Phase 5):
    bool p2p = false;
    bool p2p_create = false;        // create chain + write dist + publish
    bool p2p_listen = false;        // install dist + subscribe + receive
    bool p2p_relay  = false;        // just subscribe + relay (no dist, no decrypt)
    std::uint16_t p2p_port = 0;
    std::string p2p_dial;           // "host:port" of bootstrap peer
};

void usage() {
    std::cout << "fb-cli  (Phase 0/1 demo client)\n"
              << "  --user NAME           your username\n"
              << "DM modes (Phase 0):\n"
              << "  --listen                          receive DMs\n"
              << "  --send  --peer NAME --text MSG    send a DM\n"
              << "Channel modes (Phase 1, SenderKeys group crypto):\n"
              << "  --channel-create --channel-name NAME --dist-file PATH --text MSG\n"
              << "                                    create chain, write dist file, send msg\n"
              << "  --channel-listen --channel-name NAME --dist-file PATH\n"
              << "                                    read dist file, subscribe, decrypt\n"
              << "  --channel-invite --channel-name NAME --peer NAME --text MSG\n"
              << "                                    in-band: DM the dist to peer + send msg\n"
              << "Common:\n"
              << "  --server HOST:PORT    default 127.0.0.1:8765\n"
              << "  --wait-ms N           how long to listen (default 5000)\n"
              << "  --linger-ms N         how long channel-create stays after sending (default 1500)\n"
              << "Default URL constant: " << fb::config::kDefaultServerUrl << "\n";
}

bool parse(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&](std::string& out) {
            if (i + 1 < argc) { out = argv[++i]; return true; }
            return false;
        };
        if (s == "--user") { if (!next(a.user)) return false; }
        else if (s == "--peer") { if (!next(a.peer)) return false; }
        else if (s == "--text") { if (!next(a.text)) return false; }
        else if (s == "--server") {
            std::string sp;
            if (!next(sp)) return false;
            auto colon = sp.find(':');
            if (colon == std::string::npos) {
                a.server_host = sp;
            } else {
                a.server_host = sp.substr(0, colon);
                a.server_port = static_cast<std::uint16_t>(std::atoi(sp.c_str() + colon + 1));
            }
        }
        else if (s == "--wait-ms") {
            std::string ms;
            if (!next(ms)) return false;
            a.wait_ms = std::atoi(ms.c_str());
        }
        else if (s == "--listen") { a.listen = true; }
        else if (s == "--send") { a.send = true; }
        else if (s == "--channel-name") { if (!next(a.channel_name)) return false; }
        else if (s == "--dist-file") { if (!next(a.dist_file)) return false; }
        else if (s == "--channel-create") { a.channel_create = true; }
        else if (s == "--channel-listen") { a.channel_listen = true; }
        else if (s == "--channel-invite") { a.channel_invite = true; }
        else if (s == "--p2p-create") { a.p2p = true; a.p2p_create = true; }
        else if (s == "--p2p-listen") { a.p2p = true; a.p2p_listen = true; }
        else if (s == "--p2p-relay")  { a.p2p = true; a.p2p_relay  = true; }
        else if (s == "--p2p-port") {
            std::string p;
            if (!next(p)) return false;
            a.p2p_port = static_cast<std::uint16_t>(std::atoi(p.c_str()));
        }
        else if (s == "--p2p-dial") { if (!next(a.p2p_dial)) return false; }
        else if (s == "--linger-ms") {
            std::string ms;
            if (!next(ms)) return false;
            a.linger_ms = std::atoi(ms.c_str());
        }
        else if (s == "--help" || s == "-h") { usage(); std::exit(0); }
        else { std::cerr << "unknown arg: " << s << "\n"; usage(); return false; }
    }
    if (a.user.empty()) return false;
    const int modes = (a.send ? 1 : 0) + (a.listen ? 1 : 0) +
                      (a.channel_create ? 1 : 0) + (a.channel_listen ? 1 : 0) +
                      (a.channel_invite ? 1 : 0) +
                      (a.p2p_create ? 1 : 0) + (a.p2p_listen ? 1 : 0) +
                      (a.p2p_relay ? 1 : 0);
    if (modes != 1) return false;
    if (a.send && (a.peer.empty() || a.text.empty())) return false;
    if (a.channel_create &&
        (a.channel_name.empty() || a.dist_file.empty() || a.text.empty())) return false;
    if (a.channel_listen &&
        (a.channel_name.empty() || a.dist_file.empty())) return false;
    if (a.channel_invite &&
        (a.channel_name.empty() || a.peer.empty() || a.text.empty())) return false;
    if (a.p2p) {
        if (a.p2p_port == 0 || a.channel_name.empty()) return false;
        if (!a.p2p_relay && a.dist_file.empty()) return false;
        if (a.p2p_create && a.text.empty()) return false;
    }
    return true;
}

std::array<std::uint8_t, 32> channel_id_from_name(const std::string& name) {
    std::array<std::uint8_t, 32> id{};
    if (crypto_generichash(id.data(), id.size(),
                           reinterpret_cast<const std::uint8_t*>(name.data()), name.size(),
                           reinterpret_cast<const std::uint8_t*>("FinBit-Chan"),
                           11) != 0) {
        throw std::runtime_error("crypto_generichash failed");
    }
    return id;
}

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, std::span<const std::uint8_t> bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

// Derive a per-identity X25519 keypair deterministically from the Ed25519
// secret-key seed bytes. (libsodium gives us crypto_sign_ed25519_sk_to_curve25519
// which converts Ed25519 secret to X25519 private; pair with sk_to_pk + the
// matching pub conversion.) This is a Phase-0 shortcut; production rotates a
// separate signed prekey.
struct X25519Pair {
    std::array<std::uint8_t, 32> pub{};
    std::array<std::uint8_t, 32> priv{};
};

X25519Pair derive_x25519(const fb::crypto::Identity& id) {
    X25519Pair k;
    auto sec = id.secret_key();
    if (crypto_sign_ed25519_sk_to_curve25519(k.priv.data(), sec.data()) != 0) {
        throw std::runtime_error("ed25519_sk_to_curve25519 failed");
    }
    if (crypto_sign_ed25519_pk_to_curve25519(k.pub.data(), id.public_key().data()) != 0) {
        throw std::runtime_error("ed25519_pk_to_curve25519 failed");
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

// Pack a plain text DM body into a DmPayload protobuf.
std::vector<std::uint8_t> pack_text_payload(const std::string& text) {
    fb::proto::DmPayload p;
    p.set_text(text);
    return serialize(p);
}

// Pack a channel-key invite into a DmPayload protobuf.
std::vector<std::uint8_t> pack_channel_key_payload(
    std::span<const std::uint8_t> channel_id,
    const std::string& channel_name,
    std::span<const std::uint8_t> distribution_blob) {
    fb::proto::DmPayload p;
    auto* ck = p.mutable_channel_key();
    ck->set_channel_id(std::string(channel_id.begin(), channel_id.end()));
    ck->set_channel_name(channel_name);
    if (!ck->mutable_distribution()->ParseFromArray(
            distribution_blob.data(), static_cast<int>(distribution_blob.size()))) {
        return {};
    }
    return serialize(p);
}

void blocking_send(fb::net::Socket& s, const std::vector<std::uint8_t>& payload) {
    auto framed = fb::net::encode_frame(std::span<const std::uint8_t>(payload.data(), payload.size()));
    std::size_t off = 0;
    while (off < framed.size()) {
        const auto n = ::send(s.fd(), framed.data() + off, framed.size() - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("send: ") + strerror(errno));
        }
        off += static_cast<std::size_t>(n);
    }
}

std::optional<std::vector<std::uint8_t>> blocking_recv_frame(fb::net::Socket& s,
                                                              fb::net::FrameDecoder& dec,
                                                              int timeout_ms) {
    std::vector<std::uint8_t> out;
    if (dec.try_pop(out) == fb::net::FrameDecoder::Status::kFrameReady) return out;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::array<std::uint8_t, 4096> buf;
    while (std::chrono::steady_clock::now() < deadline) {
        timeval tv{};
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        if (remaining <= 0) break;
        tv.tv_sec = remaining / 1'000'000;
        tv.tv_usec = remaining % 1'000'000;
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(s.fd(), &rset);
        const int sel = ::select(s.fd() + 1, &rset, nullptr, nullptr, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        if (sel == 0) return std::nullopt;
        const auto n = ::recv(s.fd(), buf.data(), buf.size(), 0);
        if (n <= 0) return std::nullopt;
        dec.feed(std::span<const std::uint8_t>(buf.data(), static_cast<std::size_t>(n)));
        if (dec.try_pop(out) == fb::net::FrameDecoder::Status::kFrameReady) return out;
    }
    return std::nullopt;
}

}  // namespace

int main(int argc, char** argv) {
    Args args;
    if (!parse(argc, argv, args)) {
        usage();
        return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 2;
    }

    // Deterministic identity per username (Phase 0 demo only — never do this
    // in production; identities should be persisted, not re-derived).
    std::array<std::uint8_t, fb::crypto::kIdentitySeedBytes> seed{};
    auto h = std::hash<std::string>{}(args.user);
    const std::array<std::uint32_t, 4> seed_data = {
        static_cast<std::uint32_t>(h), static_cast<std::uint32_t>(h >> 32),
        0x46U, 0x42U  // 'F', 'B'
    };
    std::seed_seq sseq(seed_data.begin(), seed_data.end());
    std::mt19937 rng(sseq);
    for (auto& b : seed) b = static_cast<std::uint8_t>(rng() & 0xff);
    auto identity = fb::crypto::Identity::from_seed(seed);
    auto x25519 = derive_x25519(identity);

    std::cerr << "[fb-cli] user=" << args.user
              << " fingerprint=" << identity.fingerprint() << "\n";

    // ---- P2P mode (Phase 5) — server-less ---------------------------------
    if (args.p2p) {
        std::vector<std::uint8_t> pubkey(identity.public_key().begin(),
                                         identity.public_key().end());
        fb::p2p::P2PNode node("127.0.0.1", args.p2p_port,
                              std::span<const std::uint8_t>(pubkey.data(), pubkey.size()));
        node.start();
        std::cerr << "[fb-cli] p2p node listening on " << node.addr() << "\n";

        if (!args.p2p_dial.empty()) {
            const auto colon = args.p2p_dial.find(':');
            if (colon == std::string::npos) {
                std::cerr << "[fb-cli] --p2p-dial expects host:port\n";
                return 9;
            }
            const std::string dial_host = args.p2p_dial.substr(0, colon);
            const auto dial_port = static_cast<std::uint16_t>(
                std::atoi(args.p2p_dial.c_str() + colon + 1));
            try {
                node.dial(dial_host, dial_port);
                std::cerr << "[fb-cli] dialed " << dial_host << ":" << dial_port << "\n";
            } catch (const std::exception& e) {
                std::cerr << "[fb-cli] dial failed: " << e.what() << "\n";
            }
        }

        const std::string topic = args.channel_name;
        node.subscribe(topic);
        // Allow handshakes + subscription propagation.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (args.p2p_relay) {
            // Pure relay: subscribe (so relays for this topic prefer us) but
            // do not install any distribution. Stay alive for wait_ms then
            // exit. This proves blind-relay semantics — we forward bytes we
            // cannot read.
            std::this_thread::sleep_for(std::chrono::milliseconds(args.wait_ms));
            node.stop();
            return 0;
        }

        if (args.p2p_create) {
            fb::crypto::GroupSession session;
            auto dist = session.create_own_send_chain();
            write_file(args.dist_file, std::span<const std::uint8_t>(dist.data(), dist.size()));
            std::cerr << "[fb-cli] wrote distribution to " << args.dist_file << "\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(args.linger_ms));

            std::vector<std::uint8_t> pt(args.text.begin(), args.text.end());
            auto msg = session.encrypt(std::span<const std::uint8_t>(pt.data(), pt.size()), {});

            // Publish a small protobuf {sender_pubkey, sender_keys_msg}.
            // Hand-rolled framing: [u8 32 sender_pubkey][rest = sender_keys_msg]
            std::vector<std::uint8_t> framed;
            framed.reserve(32 + msg.size());
            framed.insert(framed.end(), identity.public_key().begin(),
                          identity.public_key().end());
            framed.insert(framed.end(), msg.begin(), msg.end());
            node.publish(topic,
                         std::span<const std::uint8_t>(framed.data(), framed.size()), 4);
            std::cerr << "[fb-cli] p2p published " << pt.size() << "B plaintext\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(args.linger_ms));
            node.stop();
            return 0;
        }

        // p2p-listen
        fb::crypto::GroupSession session;
        std::vector<std::uint8_t> dist;
        const auto deadline_dist =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(args.wait_ms);
        while (std::chrono::steady_clock::now() < deadline_dist) {
            try {
                dist = read_file(args.dist_file);
                if (!dist.empty()) break;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        if (dist.empty()) {
            std::cerr << "[fb-cli] timed out waiting for distribution\n";
            node.stop();
            return 8;
        }
        bool installed = false;
        std::mutex mu;
        std::condition_variable cv;
        std::vector<std::string> received;
        node.set_on_topic_message([&](const std::string& /*t*/,
                                       std::span<const std::uint8_t> payload,
                                       const fb::p2p::PeerInfo& /*origin*/) {
            if (payload.size() < 32) return;
            std::vector<std::uint8_t> sender_pub(payload.begin(), payload.begin() + 32);
            std::vector<std::uint8_t> inner(payload.begin() + 32, payload.end());
            std::lock_guard lk(mu);
            if (!installed) {
                try {
                    session.install_peer_distribution(
                        std::span<const std::uint8_t>(sender_pub.data(), sender_pub.size()),
                        std::span<const std::uint8_t>(dist.data(), dist.size()));
                    installed = true;
                } catch (...) {
                    return;
                }
            }
            auto pt = session.decrypt(
                std::span<const std::uint8_t>(sender_pub.data(), sender_pub.size()),
                std::span<const std::uint8_t>(inner.data(), inner.size()), {});
            if (pt) {
                received.emplace_back(pt->begin(), pt->end());
                cv.notify_all();
            }
        });

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(args.wait_ms);
        {
            std::unique_lock lk(mu);
            cv.wait_until(lk, deadline, [&] { return !received.empty(); });
            for (const auto& m : received) {
                std::cout << "P2P-MSG: " << m << std::endl;
            }
        }
        node.stop();
        return 0;
    }

    auto sock = fb::net::tcp_connect(args.server_host, args.server_port);
    fb::net::FrameDecoder dec;

    // 1. Send ClientHello
    {
        fb::proto::Frame f;
        auto* hello = f.mutable_hello();
        hello->set_identity_pubkey(std::string(
            reinterpret_cast<const char*>(identity.public_key().data()),
            identity.public_key().size()));
        hello->set_username(args.user);
        hello->set_protocol_version(fb::config::kProtocolVersion);
        blocking_send(sock, serialize(f));
    }
    auto hello_resp = blocking_recv_frame(sock, dec, 2000);
    if (!hello_resp) { std::cerr << "no ServerHello\n"; return 3; }
    {
        fb::proto::Frame f;
        if (!f.ParseFromArray(hello_resp->data(), static_cast<int>(hello_resp->size())) ||
            f.body_case() != fb::proto::Frame::kServerHello || !f.server_hello().accepted()) {
            std::cerr << "ServerHello rejected\n"; return 4;
        }
        // Sign the challenge and send HelloAck.
        const auto& chall = f.server_hello().server_random();
        if (chall.size() != 32) {
            std::cerr << "bad challenge size\n"; return 4;
        }
        std::vector<std::uint8_t> chall_bytes(chall.begin(), chall.end());
        auto sig = identity.sign(
            std::span<const std::uint8_t>(chall_bytes.data(), chall_bytes.size()));
        fb::proto::Frame ackf;
        ackf.mutable_hello_ack()->set_signature(
            std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));
        blocking_send(sock, serialize(ackf));
    }

    // 2. Upload prekey bundle (the X25519 pub is the signed prekey).
    {
        fb::proto::Frame f;
        auto* up = f.mutable_key_upload();
        auto* b = up->mutable_bundle();
        b->set_identity_pubkey(std::string(
            reinterpret_cast<const char*>(identity.public_key().data()),
            identity.public_key().size()));
        b->set_signed_prekey(std::string(
            reinterpret_cast<const char*>(x25519.pub.data()), x25519.pub.size()));
        // Phase 0: skip OPK and the SPK Ed25519 signature for brevity. Both
        // are required in production; the wire format already carries them.
        b->set_published_at_ms(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count()));
        blocking_send(sock, serialize(f));
    }

    // ---- In-band channel invite (Phase 1, no shared file) -----------------
    if (args.channel_invite) {
        const auto chan_id = channel_id_from_name(args.channel_name);
        // 1. Fetch peer prekey.
        {
            fb::proto::Frame f;
            f.mutable_key_fetch()->set_username(args.peer);
            blocking_send(sock, serialize(f));
        }
        auto resp = blocking_recv_frame(sock, dec, 2000);
        if (!resp) { std::cerr << "no key bundle response\n"; return 5; }
        fb::proto::Frame f;
        if (!f.ParseFromArray(resp->data(), static_cast<int>(resp->size())) ||
            f.body_case() != fb::proto::Frame::kKeyFetchResp ||
            !f.key_fetch_resp().found()) {
            std::cerr << "peer not registered yet\n"; return 6;
        }
        const auto& peer_b = f.key_fetch_resp().bundle();
        if (peer_b.signed_prekey().size() != 32 ||
            peer_b.identity_pubkey().size() != 32) {
            std::cerr << "malformed peer bundle\n"; return 7;
        }
        std::array<std::uint8_t, 32> peer_x{};
        std::memcpy(peer_x.data(), peer_b.signed_prekey().data(), 32);
        auto shared = derive_shared_secret(x25519, std::span<const std::uint8_t, 32>(peer_x));
        auto rat = fb::crypto::DoubleRatchet::init_alice(
            shared, std::span<const std::uint8_t, 32>(peer_x));

        // 2. Create our SenderKeys distribution + subscribe.
        fb::crypto::GroupSession session;
        auto own_dist = session.create_own_send_chain();
        {
            fb::proto::Frame subf;
            subf.mutable_chan_subscribe()->set_channel_group_id(
                std::string(reinterpret_cast<const char*>(chan_id.data()),
                            chan_id.size()));
            blocking_send(sock, serialize(subf));
        }

        // 3. Pack the distribution into a DmPayload.channel_key and DM-send
        //    it to the peer through the existing Double Ratchet.
        auto invite_payload = pack_channel_key_payload(
            std::span<const std::uint8_t>(chan_id.data(), chan_id.size()),
            args.channel_name,
            std::span<const std::uint8_t>(own_dist.data(), own_dist.size()));
        auto invite_inner = rat.encrypt(
            std::span<const std::uint8_t>(invite_payload.data(), invite_payload.size()), {});
        {
            fb::proto::Frame envf;
            auto* env = envf.mutable_envelope();
            std::vector<std::uint8_t> envid(16);
            randombytes_buf(envid.data(), envid.size());
            env->set_envelope_id(std::string(envid.begin(), envid.end()));
            env->set_timestamp_ms(static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count()));
            env->set_user_pubkey(peer_b.identity_pubkey());
            env->set_sender_pubkey(std::string(
                reinterpret_cast<const char*>(identity.public_key().data()),
                identity.public_key().size()));
            env->set_ciphertext(std::string(invite_inner.begin(), invite_inner.end()));
            env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
            env->set_protocol_version(fb::config::kProtocolVersion);
            blocking_send(sock, serialize(envf));
        }
        std::cerr << "[fb-cli] invited " << args.peer << " to #" << args.channel_name
                  << " via DM\n";

        // 4. Wait briefly so the peer can install + subscribe before we publish.
        std::this_thread::sleep_for(std::chrono::milliseconds(args.linger_ms));

        // 5. Publish the channel message.
        std::vector<std::uint8_t> pt(args.text.begin(), args.text.end());
        auto chan_inner = session.encrypt(
            std::span<const std::uint8_t>(pt.data(), pt.size()), {});
        fb::proto::Frame envf;
        auto* env = envf.mutable_envelope();
        std::vector<std::uint8_t> envid(16);
        randombytes_buf(envid.data(), envid.size());
        env->set_envelope_id(std::string(envid.begin(), envid.end()));
        env->set_timestamp_ms(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count()));
        env->set_channel_group_id(std::string(reinterpret_cast<const char*>(chan_id.data()),
                                               chan_id.size()));
        env->set_sender_pubkey(std::string(
            reinterpret_cast<const char*>(identity.public_key().data()),
            identity.public_key().size()));
        env->set_ciphertext(std::string(chan_inner.begin(), chan_inner.end()));
        env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
        env->set_protocol_version(fb::config::kProtocolVersion);
        blocking_send(sock, serialize(envf));
        std::cerr << "[fb-cli] sent channel msg (" << pt.size() << "B plaintext) to #"
                  << args.channel_name << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(args.linger_ms));
        return 0;
    }

    // ---- Channel mode (Phase 1) -------------------------------------------
    if (args.channel_create || args.channel_listen) {
        const auto chan_id = channel_id_from_name(args.channel_name);

        // Subscribe to the channel.
        {
            fb::proto::Frame f;
            f.mutable_chan_subscribe()->set_channel_group_id(
                std::string(reinterpret_cast<const char*>(chan_id.data()), chan_id.size()));
            blocking_send(sock, serialize(f));
        }

        if (args.channel_create) {
            fb::crypto::GroupSession session;
            auto dist = session.create_own_send_chain();
            write_file(args.dist_file, std::span<const std::uint8_t>(dist.data(), dist.size()));
            std::cerr << "[fb-cli] wrote distribution to " << args.dist_file << "\n";

            // Wait briefly so other peers can read the dist file and subscribe.
            std::this_thread::sleep_for(std::chrono::milliseconds(args.linger_ms));

            std::vector<std::uint8_t> pt(args.text.begin(), args.text.end());
            auto msg = session.encrypt(std::span<const std::uint8_t>(pt.data(), pt.size()), {});

            fb::proto::Frame f2;
            auto* env = f2.mutable_envelope();
            std::vector<std::uint8_t> envid(16);
            randombytes_buf(envid.data(), envid.size());
            env->set_envelope_id(std::string(envid.begin(), envid.end()));
            env->set_timestamp_ms(static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count()));
            env->set_channel_group_id(
                std::string(reinterpret_cast<const char*>(chan_id.data()), chan_id.size()));
            env->set_sender_pubkey(std::string(
                reinterpret_cast<const char*>(identity.public_key().data()),
                identity.public_key().size()));
            env->set_ciphertext(std::string(msg.begin(), msg.end()));
            env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
            env->set_protocol_version(fb::config::kProtocolVersion);
            blocking_send(sock, serialize(f2));
            std::cerr << "[fb-cli] sent channel msg (" << pt.size() << "B plaintext)\n";

            // Linger so the server has time to fan out before we close.
            std::this_thread::sleep_for(std::chrono::milliseconds(args.linger_ms));
            return 0;
        }

        // channel_listen
        fb::crypto::GroupSession session;
        // Read the distribution; if file isn't there yet, poll.
        std::vector<std::uint8_t> dist;
        const auto deadline_dist =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(args.wait_ms);
        while (std::chrono::steady_clock::now() < deadline_dist) {
            try {
                dist = read_file(args.dist_file);
                if (!dist.empty()) break;
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        if (dist.empty()) {
            std::cerr << "[fb-cli] timed out waiting for distribution at "
                      << args.dist_file << "\n";
            return 8;
        }

        // We don't yet know the sender's pubkey when we install. The
        // first envelope we receive carries it; install lazily then.
        bool installed = false;

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(args.wait_ms);
        while (g_run && std::chrono::steady_clock::now() < deadline) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();
            if (remaining <= 0) break;
            auto frame = blocking_recv_frame(sock, dec, static_cast<int>(remaining));
            if (!frame) continue;
            fb::proto::Frame f;
            if (!f.ParseFromArray(frame->data(), static_cast<int>(frame->size()))) continue;
            if (f.body_case() != fb::proto::Frame::kEnvelope) continue;
            const auto& env = f.envelope();
            if (env.recipient_case() != fb::proto::Envelope::kChannelGroupId) continue;
            if (env.sender_pubkey().size() != 32) continue;
            std::vector<std::uint8_t> sender_pub(env.sender_pubkey().begin(),
                                                 env.sender_pubkey().end());
            if (!installed) {
                session.install_peer_distribution(
                    std::span<const std::uint8_t>(sender_pub.data(), sender_pub.size()),
                    std::span<const std::uint8_t>(dist.data(), dist.size()));
                installed = true;
            }
            auto pt = session.decrypt(
                std::span<const std::uint8_t>(sender_pub.data(), sender_pub.size()),
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(env.ciphertext().data()),
                    env.ciphertext().size()),
                {});
            if (!pt) {
                std::cerr << "[fb-cli] channel decrypt failed\n";
                continue;
            }
            std::cout << "CHAN-MSG: " << std::string(pt->begin(), pt->end()) << std::endl;
        }
        return 0;
    }

    if (args.send) {
        // 3. Fetch peer bundle.
        {
            fb::proto::Frame f;
            f.mutable_key_fetch()->set_username(args.peer);
            blocking_send(sock, serialize(f));
        }
        auto resp = blocking_recv_frame(sock, dec, 2000);
        if (!resp) { std::cerr << "no key bundle response\n"; return 5; }
        fb::proto::Frame f;
        if (!f.ParseFromArray(resp->data(), static_cast<int>(resp->size())) ||
            f.body_case() != fb::proto::Frame::kKeyFetchResp || !f.key_fetch_resp().found()) {
            std::cerr << "peer not registered yet\n"; return 6;
        }
        const auto& peer_b = f.key_fetch_resp().bundle();
        if (peer_b.signed_prekey().size() != 32 ||
            peer_b.identity_pubkey().size() != 32) {
            std::cerr << "malformed peer bundle\n"; return 7;
        }
        std::array<std::uint8_t, 32> peer_x{};
        std::memcpy(peer_x.data(), peer_b.signed_prekey().data(), 32);
        auto shared = derive_shared_secret(x25519, std::span<const std::uint8_t, 32>(peer_x));

        auto rat = fb::crypto::DoubleRatchet::init_alice(shared, std::span<const std::uint8_t, 32>(peer_x));
        // Inner DM body is now a serialized DmPayload protobuf so receivers
        // can route between text and channel-key invites.
        const auto pt = pack_text_payload(args.text);
        std::vector<std::uint8_t> outer_aad;
        auto inner = rat.encrypt(std::span<const std::uint8_t>(pt.data(), pt.size()),
                                 std::span<const std::uint8_t>(outer_aad.data(), outer_aad.size()));

        // 4. Build Envelope. ciphertext = inner ratchet message bytes.
        // (For Phase 0 we don't add a second AEAD layer between ratchet and
        // envelope; the ratchet's AEAD already covers integrity.)
        fb::proto::Frame f2;
        auto* env = f2.mutable_envelope();
        std::vector<std::uint8_t> envid(16);
        randombytes_buf(envid.data(), envid.size());
        env->set_envelope_id(std::string(envid.begin(), envid.end()));
        const auto now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        env->set_timestamp_ms(now_ms);
        env->set_user_pubkey(peer_b.identity_pubkey());
        env->set_sender_pubkey(std::string(
            reinterpret_cast<const char*>(identity.public_key().data()),
            identity.public_key().size()));
        env->set_ciphertext(std::string(inner.begin(), inner.end()));
        env->set_aead_alg(fb::config::aead_alg::kAes256Gcm);
        env->set_protocol_version(fb::config::kProtocolVersion);
        blocking_send(sock, serialize(f2));
        std::cerr << "[fb-cli] sent " << args.text.size() << "B plaintext to " << args.peer
                  << "\n";
        return 0;
    }

    // listen mode — handles BOTH plain DM text and channel-key invites that
    // arrive over DM, plus channel envelopes that follow once we've installed
    // the distribution.
    std::optional<fb::crypto::DoubleRatchet> rat;
    fb::crypto::GroupSession group_session;
    // channel_id (32 bytes) -> display name we learned from the invite
    std::map<std::string, std::string> known_channels;

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(args.wait_ms);
    while (g_run && std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        if (remaining <= 0) break;
        auto frame = blocking_recv_frame(sock, dec, static_cast<int>(remaining));
        if (!frame) continue;
        fb::proto::Frame f;
        if (!f.ParseFromArray(frame->data(), static_cast<int>(frame->size()))) continue;
        if (f.body_case() == fb::proto::Frame::kUsernameResp) {
            const auto& r = f.username_resp();
            if (r.found()) {
                std::cout << "USER: " << r.username() << std::endl;
            }
            continue;
        }
        if (f.body_case() != fb::proto::Frame::kEnvelope) continue;
        const auto& env = f.envelope();

        // ---- channel envelope path ---------------------------------------
        if (env.recipient_case() == fb::proto::Envelope::kChannelGroupId) {
            if (env.sender_pubkey().size() != 32) continue;
            const std::string sender_pub_bytes(env.sender_pubkey().begin(),
                                                env.sender_pubkey().end());
            const std::string ch_id(env.channel_group_id().begin(),
                                    env.channel_group_id().end());
            auto nit = known_channels.find(ch_id);
            const std::string name = (nit != known_channels.end()) ? nit->second
                                                                    : std::string{"<unknown>"};
            auto pt = group_session.decrypt(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(sender_pub_bytes.data()),
                    sender_pub_bytes.size()),
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(env.ciphertext().data()),
                    env.ciphertext().size()),
                {});
            if (!pt) continue;  // sender we haven't been invited from
            std::cout << "CHAN-MSG: " << std::string(pt->begin(), pt->end()) << std::endl;
            (void)name;  // (could prefix the line with #name)
            continue;
        }

        // ---- DM envelope path --------------------------------------------
        if (!rat) {
            if (env.sender_pubkey().size() != 32) continue;
            std::array<std::uint8_t, 32> peer_x{};
            if (crypto_sign_ed25519_pk_to_curve25519(
                    peer_x.data(),
                    reinterpret_cast<const std::uint8_t*>(env.sender_pubkey().data())) != 0) {
                continue;
            }
            auto shared = derive_shared_secret(x25519, std::span<const std::uint8_t, 32>(peer_x));
            rat.emplace(fb::crypto::DoubleRatchet::init_bob(
                std::span<const std::uint8_t, 32>(shared.data(), shared.size()),
                std::span<const std::uint8_t, 32>(x25519.priv.data(), 32),
                std::span<const std::uint8_t, 32>(x25519.pub.data(), 32)));
        }
        auto pt = rat->decrypt(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(env.ciphertext().data()),
                env.ciphertext().size()),
            {});
        if (!pt) {
            std::cerr << "[fb-cli] dm decrypt failed\n";
            continue;
        }
        // Inner body is a DmPayload.
        fb::proto::DmPayload payload;
        if (!payload.ParseFromArray(pt->data(), static_cast<int>(pt->size()))) {
            std::cerr << "[fb-cli] DmPayload parse failed\n";
            continue;
        }
        if (payload.body_case() == fb::proto::DmPayload::kText) {
            // Optimistically request the sender's username so the line shows
            // "alice: hi" instead of just the fingerprint. We don't block on
            // the response — the next listener iteration picks it up.
            {
                fb::proto::Frame qf;
                qf.mutable_username_lookup()->set_pubkey(env.sender_pubkey());
                blocking_send(sock, serialize(qf));
            }
            std::cout << "MSG: " << payload.text() << std::endl;
        } else if (payload.body_case() == fb::proto::DmPayload::kChannelKey) {
            const auto& ck = payload.channel_key();
            if (ck.channel_id().size() != 32) continue;
            // Install the sender's distribution into our group session.
            std::vector<std::uint8_t> dist_blob(ck.distribution().ByteSizeLong());
            if (!ck.distribution().SerializeToArray(dist_blob.data(),
                                                    static_cast<int>(dist_blob.size()))) {
                continue;
            }
            try {
                group_session.install_peer_distribution(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(env.sender_pubkey().data()),
                        env.sender_pubkey().size()),
                    std::span<const std::uint8_t>(dist_blob.data(), dist_blob.size()));
            } catch (...) {
                continue;
            }
            // Subscribe to the channel so the server fans out future envelopes.
            fb::proto::Frame subf;
            subf.mutable_chan_subscribe()->set_channel_group_id(ck.channel_id());
            blocking_send(sock, serialize(subf));
            known_channels[ck.channel_id()] = ck.channel_name();
            std::cout << "INVITE: #" << ck.channel_name() << std::endl;
        }
    }
    return 0;
}
