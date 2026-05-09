// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// fb_server — FinBit centralized blind relay (Phase 0).
//
// Single-threaded epoll loop. Per-connection FrameDecoder buffers incoming
// bytes into Frame protobufs; outgoing bytes are buffered in a per-connection
// write queue (drained on EPOLLOUT).
//
// The server NEVER decrypts envelope.ciphertext. It uses the recipient field
// to route by recipient pubkey, applies a per-pubkey token bucket on the
// SENDER side (rate-limit who sends, not who receives), and persists offline
// envelopes until the recipient reconnects.
//
// Logging: all log lines are emitted via spdlog at info/warn level. None of
// them include envelope ciphertext or any field that could reveal plaintext.
// The end-to-end test greps server logs for plaintext markers and asserts
// they never appear.
// =============================================================================

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>      // IFF_UP / IFF_LOOPBACK
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#if FB_HAVE_OPENSSL
#  include <openssl/err.h>
#  include <openssl/ssl.h>
#endif

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "fb/config/build_config.hpp"
#include "fb/crypto/identity.hpp"
#include "fb/net/frame_codec.hpp"
#include "fb/net/io_loop.hpp"
#include "fb/net/tcp.hpp"
#include "fb/net/websocket.hpp"
#include "fb/ratelimit/token_bucket.hpp"

#include "directory.hpp"
#include "envelope.pb.h"
#include "handshake.pb.h"
#include "relay.hpp"

#include <sodium.h>

namespace {

enum class Transport { kTcp, kWs };

// Walk every up + non-loopback interface and return their IPv4/IPv6
// addresses in printable form. Used to print a "your server is reachable
// at..." cheatsheet when bound to 0.0.0.0 so the operator doesn't have to
// `ip addr` to find a URL to share.
std::vector<std::string> external_addresses() {
    std::vector<std::string> out;
    ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0 || !head) return out;
    for (ifaddrs* p = head; p; p = p->ifa_next) {
        if (!p->ifa_addr || !(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        char buf[INET6_ADDRSTRLEN] = {0};
        if (p->ifa_addr->sa_family == AF_INET) {
            const auto* a = reinterpret_cast<const sockaddr_in*>(p->ifa_addr);
            inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf));
            out.emplace_back(buf);
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            const auto* a = reinterpret_cast<const sockaddr_in6*>(p->ifa_addr);
            // Skip link-local (fe80::) — not useful for sharing.
            if ((a->sin6_addr.s6_addr[0] == 0xfe) &&
                ((a->sin6_addr.s6_addr[1] & 0xc0) == 0x80)) continue;
            inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf));
            out.emplace_back(std::string("[") + buf + "]");
        }
    }
    freeifaddrs(head);
    return out;
}

struct Conn {
    fb::net::Socket sock;
    Transport transport = Transport::kTcp;
    // TCP path:
    fb::net::FrameDecoder dec;
    // WS path:
    fb::net::ws::HandshakeParser ws_handshake;
    fb::net::ws::FrameParser     ws_parser;
    bool ws_upgraded = false;
    std::vector<std::uint8_t> write_buf;
    std::vector<std::uint8_t> claimed_user_pub;  // populated on ClientHello, not yet trusted
    std::vector<std::uint8_t> bound_user_pub;    // populated only after HelloAck signature verifies
    std::array<std::uint8_t, 32> challenge{};
    bool challenge_issued = false;
    bool authenticated   = false;
    std::string claimed_username;
    bool wants_close = false;

#if FB_HAVE_OPENSSL
    // Set when the connection was accepted on the TLS listener. Owned by
    // Conn — destructor cleans up. Until tls_handshake_done is true,
    // every read/write attempt drives SSL_accept until OpenSSL signals
    // the handshake is complete.
    SSL* ssl = nullptr;
    bool tls_handshake_done = false;
#endif

    ~Conn() {
#if FB_HAVE_OPENSSL
        if (ssl) {
            // Best-effort shutdown — peer may be gone already.
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
#endif
    }

    // Unified read/write surface. Routes through OpenSSL when ssl != null,
    // otherwise straight to the underlying socket. Return values match
    // fb::net::Socket: positive = bytes, 0 = peer closed, kReadRetry =
    // would-block, negative = error.
    std::ptrdiff_t read_some(std::span<std::uint8_t> buf) {
#if FB_HAVE_OPENSSL
        if (ssl) {
            if (!tls_handshake_done) {
                int rc = SSL_accept(ssl);
                if (rc <= 0) {
                    int e = SSL_get_error(ssl, rc);
                    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                        return fb::net::Socket::kReadRetry;
                    }
                    return -1;   // handshake failed
                }
                tls_handshake_done = true;
                // Fall through to SSL_read — the same TCP packet that
                // completed the handshake may have application data
                // tail-piggybacked. Returning kReadRetry here would
                // park the loop waiting for an EPOLLIN that never
                // comes (the data is in OpenSSL's buffer, not the
                // socket).
            }
            int rc = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
            if (rc > 0) return rc;
            int e = SSL_get_error(ssl, rc);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                return fb::net::Socket::kReadRetry;
            }
            if (e == SSL_ERROR_ZERO_RETURN) return 0;  // clean close_notify
            return -1;
        }
#endif
        return sock.read_some(buf);
    }

    std::ptrdiff_t write_some(std::span<const std::uint8_t> buf) {
#if FB_HAVE_OPENSSL
        if (ssl) {
            if (!tls_handshake_done) {
                int rc = SSL_accept(ssl);
                if (rc <= 0) {
                    int e = SSL_get_error(ssl, rc);
                    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                        return 0;  // try again next EPOLLOUT
                    }
                    return -1;
                }
                tls_handshake_done = true;
            }
            int rc = SSL_write(ssl, buf.data(), static_cast<int>(buf.size()));
            if (rc > 0) return rc;
            int e = SSL_get_error(ssl, rc);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return 0;
            return -1;
        }
#endif
        return sock.write_some(buf);
    }
};

std::atomic_bool g_run{true};
void on_signal(int) { g_run = false; }

void enqueue_write(fb::net::IoLoop& loop, Conn& c, const std::vector<std::uint8_t>& payload) {
    if (c.transport == Transport::kWs) {
        // Each WS binary message carries exactly one serialized Frame —
        // WS gives us message boundaries, no need for the inner length prefix.
        auto frame = fb::net::ws::build_server_binary_frame(
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        c.write_buf.insert(c.write_buf.end(), frame.begin(), frame.end());
    } else {
        auto framed = fb::net::encode_frame(
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        c.write_buf.insert(c.write_buf.end(), framed.begin(), framed.end());
    }
    loop.mod_fd(c.sock.fd(), EPOLLIN | EPOLLOUT | EPOLLET);
}

std::vector<std::uint8_t> serialize(const google::protobuf::MessageLite& m) {
    std::vector<std::uint8_t> out(m.ByteSizeLong());
    if (!m.SerializeToArray(out.data(), static_cast<int>(out.size()))) {
        out.clear();
    }
    return out;
}

void send_server_hello(fb::net::IoLoop& loop, Conn& c, bool ok, const std::string& detail,
                       std::span<const std::uint8_t> challenge = {}) {
    fb::proto::Frame f;
    auto* hello = f.mutable_server_hello();
    hello->set_accepted(ok);
    hello->set_detail(detail);
    if (!challenge.empty()) {
        hello->set_server_random(std::string(challenge.begin(), challenge.end()));
    }
    enqueue_write(loop, c, serialize(f));
}

}  // namespace

int main(int argc, char** argv) {
    std::string bind_host = "127.0.0.1";
    std::uint16_t port = 8765;
    std::uint16_t ws_port = 0;       // 0 = disabled
    std::uint16_t tls_port = 0;      // 0 = disabled (built-in TLS WS)
    std::uint16_t tls_raw_port = 0;  // 0 = disabled (TLS-wrapped raw frames
                                      // — same wire shape as --port, just
                                      // with a TLS layer below. Lets native
                                      // clients run on a likely-open port
                                      // like 443 without speaking WS.)
    std::string tls_cert, tls_key;
    std::string offline_db;
    bool public_listen = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--host" && i + 1 < argc) bind_host = argv[++i];
        else if (a == "--ws-port" && i + 1 < argc)
            ws_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--tls-port" && i + 1 < argc)
            tls_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--tls-raw-port" && i + 1 < argc)
            tls_raw_port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--tls-cert" && i + 1 < argc) tls_cert = argv[++i];
        else if (a == "--tls-key"  && i + 1 < argc) tls_key  = argv[++i];
        else if (a == "--offline-db" && i + 1 < argc) offline_db = argv[++i];
        else if (a == "--public") public_listen = true;
        else if (a == "--help" || a == "-h") {
            std::cerr <<
                "usage: fb_server [--host H] [--port P] [--ws-port P]\n"
                "                 [--public] [--offline-db PATH]\n"
                "\n"
                "Listening:\n"
                "  --host H        bind address (default 127.0.0.1 — localhost only)\n"
                "  --public        shortcut for --host 0.0.0.0 (listen on every\n"
                "                  interface — required for remote clients)\n"
                "  --port P        TCP listener port for native clients (default 8765)\n"
                "  --ws-port P     WebSocket listener for browser/Node clients (default off)\n"
                "  --tls-port P    TLS-wrapped WebSocket (wss://) — for browsers from\n"
                "                  https:// pages without a reverse proxy. Requires\n"
                "                  --tls-cert and --tls-key.\n"
                "  --tls-raw-port P TLS-wrapped raw-frame transport for native clients\n"
                "                  (fb-cli --tls / desktop client TLS mode). Same\n"
                "                  protocol as --port but on TLS — looks like HTTPS\n"
                "                  to a network observer, fits anywhere :443 is open.\n"
                "                  Requires --tls-cert and --tls-key.\n"
                "  --tls-cert F    PEM file with the server certificate chain\n"
                "  --tls-key F     PEM file with the matching private key\n"
                "  --offline-db F  SQLite path for offline queue + directory persistence\n"
                "                  (defaults to in-memory; data is lost on restart)\n"
                "\n"
                "Self-signed cert for local testing:\n"
                "  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \\\n"
                "    -keyout key.pem -out cert.pem -subj /CN=localhost\n"
                "  fb_server --tls-port 8443 --tls-cert cert.pem --tls-key key.pem\n"
                "  Browsers reject self-signed certs by default — accept the warning\n"
                "  manually or import the cert into the OS trust store for testing.\n"
                "\n"
                "Going live (LAN):\n"
                "  fb_server --public --port 8765 --ws-port 8766 --offline-db /var/lib/fb.db\n"
                "  Then peers connect to ws://<your-ip>:8766\n"
                "\n"
                "Going live (Internet via reverse proxy):\n"
                "  Browsers won't ws:// from an https:// page. Put a TLS-terminating\n"
                "  proxy (caddy / nginx / traefik) in front and proxy wss:// to the\n"
                "  --ws-port. Example caddyfile fragment:\n"
                "    fb.example.com {\n"
                "      reverse_proxy /ws  127.0.0.1:8766\n"
                "    }\n"
                "\n"
                "  placeholder URL constant: " << fb::config::kDefaultServerUrl << "\n";
            return 0;
        }
    }
    if (public_listen) bind_host = "0.0.0.0";
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    fb::server::Directory dir;
    fb::server::Relay relay;
    if (!offline_db.empty()) {
        relay.enable_persistent_offline(offline_db);
        dir.enable_persistence(relay.persistent_store());
        std::fprintf(stderr, "[server] persistent state (offline queue + directory + prekeys) "
                     "at %s\n", offline_db.c_str());
    }
    fb::ratelimit::KeyedLimiter limiter(fb::config::ratelimit::kDefaultSustainedBytesPerSec,
                                        fb::config::ratelimit::kDefaultBurstBytes);

    fb::net::IoLoop loop;
    auto listener = fb::net::tcp_listen(bind_host, port);

    std::unordered_map<int, std::unique_ptr<Conn>> conns;

    // Forward-declared so close_conn can broadcast roster updates on the
    // way out without ordering pain. Body assigned right after close_conn.
    std::function<void(const std::string&)> broadcast_room_roster;

    auto close_conn = [&](int fd) {
        // Best-effort: flush whatever's in the userspace write buffer before
        // tearing the socket down. Without this, frames enqueued in the same
        // turn as wants_close=true (e.g. ControlMessage(USERNAME_TAKEN)) are
        // silently lost — the client gets a close notification with no
        // explanation. A tiny control frame fits in the TCP send buffer
        // every time; we don't loop on EAGAIN so a hostile peer with a
        // saturated socket can't deadlock us.
        auto it = conns.find(fd);
        if (it != conns.end() && !it->second->write_buf.empty()) {
            const auto& buf = it->second->write_buf;
            (void)it->second->write_some(
                std::span<const std::uint8_t>(buf.data(), buf.size()));
        }
        // Snapshot the rooms this fd was in BEFORE we forget — every
        // remaining member needs an updated roster (one fewer participant).
        const auto rooms_left = relay.room_member_rooms(fd);
        relay.unbind(fd);
        relay.unbind_all_channels(fd);
        relay.unbind_all_rooms(fd);
        loop.remove_fd(fd);
        conns.erase(fd);
        // Fan out roster updates after the disconnecting fd is fully gone
        // (so it doesn't appear in its own goodbye broadcast).
        for (const auto& rid : rooms_left) {
            broadcast_room_roster(rid);
        }
    };

    // Build a RoomRoster proto from current membership and send it to
    // every member. `room_id` is the raw 32-byte id (as a std::string).
    // No-op when the room has zero members left (last-leaver case).
    broadcast_room_roster = [&](const std::string& room_id) {
        const auto fds = relay.room_member_fds(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(room_id.data()), room_id.size()));
        if (fds.empty()) return;
        fb::proto::Frame f;
        auto* roster = f.mutable_room_roster();
        roster->set_room_id(room_id);
        roster->set_sframe_epoch(1);   // bumped by future SFrame rotation
        for (int member_fd : fds) {
            auto cit = conns.find(member_fd);
            if (cit == conns.end()) continue;
            auto* m = roster->add_participants();
            m->set_identity_pubkey(std::string(
                reinterpret_cast<const char*>(cit->second->bound_user_pub.data()),
                cit->second->bound_user_pub.size()));
            m->set_has_audio(true);
            m->set_has_video(false);   // refined by client-side capability later
        }
        const auto bytes = serialize(f);
        for (int member_fd : fds) {
            auto cit = conns.find(member_fd);
            if (cit != conns.end()) enqueue_write(loop, *cit->second, bytes);
        }
    };

    auto handle_frame = [&](Conn& c, const std::vector<std::uint8_t>& bytes) {
        fb::proto::Frame f;
        if (!f.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) {
            std::fprintf(stderr, "[server] malformed frame, closing fd=%d\n", c.sock.fd());
            c.wants_close = true;
            return;
        }
        // Pre-auth allowlist: only ClientHello + HelloAck. Drop everything
        // else (silently — a misbehaving / malicious client should not get
        // free state changes).
        if (!c.authenticated && f.body_case() != fb::proto::Frame::kHello &&
            f.body_case() != fb::proto::Frame::kHelloAck) {
            std::fprintf(stderr, "[server] dropping pre-auth frame body=%d on fd=%d\n",
                         static_cast<int>(f.body_case()), c.sock.fd());
            return;
        }
        switch (f.body_case()) {
            case fb::proto::Frame::kHello: {
                const auto& h = f.hello();
                // Refuse a second Hello on an already-authenticated
                // connection. Without this an authed client could re-arm
                // the challenge (for a different identity) and re-bind the
                // socket — handing future inbound DMs for the original
                // identity to whoever signs the new challenge. The relay
                // bind from the first auth is NOT torn down here, so the
                // window is small but real.
                if (c.authenticated || !c.bound_user_pub.empty()) {
                    std::fprintf(stderr,
                                 "[server] fd=%d second ClientHello on auth'd "
                                 "connection — refusing\n", c.sock.fd());
                    c.wants_close = true;
                    return;
                }
                if (h.identity_pubkey().size() != 32) {
                    send_server_hello(loop, c, false, "bad pubkey size");
                    c.wants_close = true;
                    return;
                }
                c.claimed_user_pub.assign(h.identity_pubkey().begin(),
                                          h.identity_pubkey().end());
                c.claimed_username = h.username();
                // Issue a 32-byte random challenge. The connection becomes
                // authenticated only after HelloAck delivers a valid Ed25519
                // signature over this challenge.
                randombytes_buf(c.challenge.data(), c.challenge.size());
                c.challenge_issued = true;
                c.authenticated = false;
                send_server_hello(loop, c, true, "challenge",
                                  std::span<const std::uint8_t>(c.challenge.data(),
                                                                 c.challenge.size()));
                std::fprintf(stderr, "[server] hello fd=%d user=%s — challenge issued\n",
                             c.sock.fd(), h.username().c_str());
                break;
            }
            case fb::proto::Frame::kHelloAck: {
                if (!c.challenge_issued || c.claimed_user_pub.size() != 32) {
                    std::fprintf(stderr, "[server] HelloAck before Hello, closing fd=%d\n",
                                 c.sock.fd());
                    c.wants_close = true;
                    return;
                }
                const auto& sig = f.hello_ack().signature();
                if (sig.size() != fb::crypto::kIdentitySigBytes) {
                    std::fprintf(stderr, "[server] bad sig size, closing fd=%d\n", c.sock.fd());
                    c.wants_close = true;
                    return;
                }
                fb::crypto::PubKey pk{};
                std::memcpy(pk.data(), c.claimed_user_pub.data(), 32);
                fb::crypto::Sig s{};
                std::memcpy(s.data(), sig.data(), s.size());
                if (!fb::crypto::Identity::verify(
                        pk,
                        std::span<const std::uint8_t>(c.challenge.data(),
                                                      c.challenge.size()),
                        s)) {
                    std::fprintf(stderr, "[server] HelloAck signature INVALID for fd=%d\n",
                                 c.sock.fd());
                    c.wants_close = true;
                    return;
                }
                if (!c.claimed_username.empty()) {
                    // register_user is idempotent for (username, same pubkey)
                    // and returns false ONLY when the username is already
                    // bound to a DIFFERENT identity. In that case the client
                    // is trying (intentionally or by accident) to impersonate
                    // an existing user — refuse the connection rather than
                    // silently bind under their real pubkey, which used to
                    // mislead the user into thinking they "got" the name.
                    bool ok = dir.register_user(
                        c.claimed_username,
                        std::span<const std::uint8_t>(c.claimed_user_pub.data(),
                                                       c.claimed_user_pub.size()));
                    if (!ok) {
                        std::fprintf(stderr,
                                     "[server] fd=%d username '%s' is bound to a "
                                     "different identity — rejecting\n",
                                     c.sock.fd(), c.claimed_username.c_str());
                        fb::proto::Frame ctrl;
                        auto* cm = ctrl.mutable_control();
                        cm->set_code(fb::proto::ControlMessage::USERNAME_TAKEN);
                        cm->set_detail("username '" + c.claimed_username +
                                       "' is registered to a different identity");
                        enqueue_write(loop, c, serialize(ctrl));
                        c.wants_close = true;
                        return;
                    }
                }
                c.bound_user_pub = c.claimed_user_pub;
                c.authenticated = true;
                relay.bind(c.sock.fd(),
                           std::span<const std::uint8_t>(c.bound_user_pub.data(),
                                                          c.bound_user_pub.size()));
                std::fprintf(stderr, "[server] fd=%d AUTHED user=%s\n", c.sock.fd(),
                             c.claimed_username.c_str());
                // Drain offline.
                auto pending = relay.drain_offline(
                    std::span<const std::uint8_t>(c.bound_user_pub.data(),
                                                   c.bound_user_pub.size()));
                for (auto& env_bytes : pending) {
                    fb::proto::Frame outf;
                    auto* env = outf.mutable_envelope();
                    if (env->ParseFromArray(env_bytes.data(),
                                            static_cast<int>(env_bytes.size()))) {
                        enqueue_write(loop, c, serialize(outf));
                    }
                }
                break;
            }
            case fb::proto::Frame::kKeyUpload: {
                const auto& up = f.key_upload();
                std::string blob;
                if (!up.bundle().SerializeToString(&blob)) {
                    std::fprintf(stderr, "[server] bundle serialize failed\n");
                    return;
                }
                // Look up which username this fd is bound to (via directory).
                // Phase 0 simplification: stash bundle keyed by base64-pubkey
                // when no username was supplied.
                std::string key_name;
                if (!c.bound_user_pub.empty()) {
                    // Find name matching pub.
                    // Cheaper: just key by pubkey hex. Server lookup later
                    // passes a name; for the demo we accept either.
                    key_name.assign(reinterpret_cast<const char*>(c.bound_user_pub.data()),
                                    c.bound_user_pub.size());
                }
                dir.put_bundle(key_name,
                               std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t*>(blob.data()), blob.size()));
                std::fprintf(stderr, "[server] prekey bundle uploaded (%zu bytes)\n", blob.size());
                break;
            }
            case fb::proto::Frame::kKeyFetch: {
                const auto& q = f.key_fetch();
                fb::proto::Frame resp;
                auto* r = resp.mutable_key_fetch_resp();
                r->set_request_id(q.request_id());   // echo for client correlation
                // Map username to pubkey, then lookup bundle.
                auto pub = dir.resolve(q.username());
                if (!pub) {
                    r->set_found(false);
                } else {
                    auto bundle =
                        dir.get_bundle(std::string(reinterpret_cast<const char*>(pub->data()),
                                                   pub->size()));
                    if (!bundle) {
                        r->set_found(false);
                    } else {
                        r->set_found(r->mutable_bundle()->ParseFromArray(
                            bundle->data(), static_cast<int>(bundle->size())));
                    }
                }
                enqueue_write(loop, c, serialize(resp));
                break;
            }
            case fb::proto::Frame::kChanSubscribe: {
                const auto& sub = f.chan_subscribe();
                if (sub.channel_group_id().size() == 32) {
                    relay.channel_subscribe(
                        c.sock.fd(),
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(sub.channel_group_id().data()),
                            32));
                    std::fprintf(stderr, "[server] fd=%d subscribed to channel\n", c.sock.fd());
                }
                break;
            }
            case fb::proto::Frame::kChanUnsubscribe: {
                const auto& uns = f.chan_unsubscribe();
                if (uns.channel_group_id().size() == 32) {
                    relay.channel_unsubscribe(
                        c.sock.fd(),
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(uns.channel_group_id().data()),
                            32));
                }
                break;
            }
            case fb::proto::Frame::kRoomJoin: {
                // Group-call signaling rendezvous (full-mesh v0).
                const auto& rj = f.room_join();
                if (rj.room_id().size() != 32) break;
                relay.room_join(
                    c.sock.fd(),
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(rj.room_id().data()), 32));
                std::fprintf(stderr,
                             "[server] fd=%d joined room (audio=%d video=%d)\n",
                             c.sock.fd(), rj.want_audio(), rj.want_video());
                broadcast_room_roster(rj.room_id());
                break;
            }
            case fb::proto::Frame::kRoomLeave: {
                const auto& rl = f.room_leave();
                if (rl.room_id().size() != 32) break;
                relay.room_leave(
                    c.sock.fd(),
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(rl.room_id().data()), 32));
                std::fprintf(stderr, "[server] fd=%d left room\n", c.sock.fd());
                broadcast_room_roster(rl.room_id());
                break;
            }
            case fb::proto::Frame::kEnvelope: {
                const auto& env = f.envelope();
                if (env.recipient_case() == fb::proto::Envelope::kChannelGroupId) {
                    if (!c.bound_user_pub.empty()) {
                        const auto ct_bytes =
                            static_cast<std::uint64_t>(env.ciphertext().size());
                        if (!limiter.try_consume(
                                std::span<const std::uint8_t>(c.bound_user_pub.data(),
                                                              c.bound_user_pub.size()),
                                ct_bytes)) {
                            return;  // silently drop on overflow for channel sends
                        }
                    }
                    const auto& gid = env.channel_group_id();
                    if (gid.size() != 32) return;
                    auto subs = relay.channel_subscribers(
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(gid.data()), 32));
                    fb::proto::Frame outf;
                    *outf.mutable_envelope() = env;
                    auto serialized = serialize(outf);
                    for (int sfd : subs) {
                        if (sfd == c.sock.fd()) continue;  // don't echo to sender
                        auto it = conns.find(sfd);
                        if (it != conns.end()) enqueue_write(loop, *it->second, serialized);
                    }
                    return;
                }
                if (env.recipient_case() != fb::proto::Envelope::kUserPubkey) {
                    std::fprintf(stderr, "[server] envelope had no usable recipient\n");
                    return;
                }
                if (!c.bound_user_pub.empty()) {
                    const auto ct_bytes = static_cast<std::uint64_t>(env.ciphertext().size());
                    if (!limiter.try_consume(
                            std::span<const std::uint8_t>(c.bound_user_pub.data(),
                                                          c.bound_user_pub.size()),
                            ct_bytes)) {
                        fb::proto::Frame ctrl;
                        auto* cm = ctrl.mutable_control();
                        cm->set_code(fb::proto::ControlMessage::RATE_EXCEEDED);
                        cm->set_in_reply_to_envelope_id(env.envelope_id());
                        cm->set_retry_after_ms(1000);
                        enqueue_write(loop, c, serialize(ctrl));
                        return;
                    }
                }
                const auto& rcpt = env.user_pubkey();
                std::vector<std::uint8_t> rcpt_bytes(rcpt.begin(), rcpt.end());
                int dst_fd = relay.lookup(std::span<const std::uint8_t>(rcpt_bytes.data(),
                                                                         rcpt_bytes.size()));
                fb::proto::Frame outf;
                *outf.mutable_envelope() = env;
                auto serialized = serialize(outf);
                if (dst_fd >= 0) {
                    auto it = conns.find(dst_fd);
                    if (it != conns.end()) {
                        enqueue_write(loop, *it->second, serialized);
                    }
                } else {
                    std::vector<std::uint8_t> envb(env.ByteSizeLong());
                    if (!env.SerializeToArray(envb.data(), static_cast<int>(envb.size()))) {
                        std::fprintf(stderr, "[server] envelope serialize failed\n");
                        return;
                    }
                    relay.enqueue_offline(std::span<const std::uint8_t>(rcpt_bytes.data(),
                                                                         rcpt_bytes.size()),
                                          std::move(envb));
                    std::fprintf(stderr,
                                 "[server] queued offline (recipient pub size=%zu)\n",
                                 rcpt_bytes.size());
                }
                break;
            }
            case fb::proto::Frame::kUsernameLookup: {
                const auto& q = f.username_lookup();
                fb::proto::Frame resp;
                auto* r = resp.mutable_username_resp();
                r->set_pubkey(q.pubkey());
                if (q.pubkey().size() == 32) {
                    auto name = dir.reverse_resolve(std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(q.pubkey().data()),
                        q.pubkey().size()));
                    if (name) {
                        r->set_username(*name);
                        r->set_found(true);
                    } else {
                        r->set_found(false);
                    }
                } else {
                    r->set_found(false);
                }
                enqueue_write(loop, c, serialize(resp));
                break;
            }
            case fb::proto::Frame::kRegisterReq: {
                const auto& req = f.register_req();
                fb::proto::Frame resp;
                auto* r = resp.mutable_register_resp();
                // Bind check: the pubkey on the claim MUST equal the
                // pubkey we authenticated this connection against. Without
                // this, an authed user could squat any free username for
                // any pubkey (their own, the lookup table just stores
                // whatever bytes you sent). Auth via challenge-response
                // already proved this connection controls bound_user_pub;
                // we only let it claim names FOR that pubkey.
                std::vector<std::uint8_t> claim_pub(
                    req.claim().identity_pubkey().begin(),
                    req.claim().identity_pubkey().end());
                if (claim_pub.size() != c.bound_user_pub.size() ||
                    !std::equal(claim_pub.begin(), claim_pub.end(),
                                c.bound_user_pub.begin())) {
                    std::fprintf(stderr,
                                 "[server] fd=%d RegisterReq claim pubkey "
                                 "doesn't match auth-bound pubkey — refusing\n",
                                 c.sock.fd());
                    r->set_accepted(false);
                    r->set_detail("claim pubkey must equal authenticated pubkey");
                    enqueue_write(loop, c, serialize(resp));
                    break;
                }
                bool ok = dir.register_user(
                    req.claim().username(),
                    std::span<const std::uint8_t>(c.bound_user_pub.data(),
                                                   c.bound_user_pub.size()));
                r->set_accepted(ok);
                r->set_detail(ok ? "ok" : "username taken");
                enqueue_write(loop, c, serialize(resp));
                break;
            }
            default:
                break;
        }
    };

    auto on_conn_ready = [&](int fd, std::uint32_t events) {
        auto it = conns.find(fd);
        if (it == conns.end()) return;
        auto& c = *it->second;

        if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            close_conn(fd);
            return;
        }
        if (events & EPOLLIN) {
            std::array<std::uint8_t, 4096> buf;
            for (;;) {
                auto n = c.read_some(std::span<std::uint8_t>(buf.data(), buf.size()));
#if FB_HAVE_OPENSSL
                // SSL_accept needs to write its ServerHello /
                // Certificate / etc. fragments before more client
                // bytes arrive. read_some + SSL_accept won't make
                // forward progress on the WRITE side without us
                // explicitly calling SSL_write — push it here by
                // calling write_some(empty), which on the SSL path
                // re-enters SSL_accept and lets OpenSSL flush any
                // pending output. Cheap no-op when handshake_done.
                if (c.ssl && !c.tls_handshake_done &&
                    n == fb::net::Socket::kReadRetry) {
                    std::array<std::uint8_t, 1> dummy{};
                    (void)c.write_some(
                        std::span<const std::uint8_t>(dummy.data(), 0));
                }
#endif
                if (n == fb::net::Socket::kReadRetry) break;
                if (n <= 0) {
                    close_conn(fd);
                    return;
                }
                std::span<const std::uint8_t> incoming(buf.data(),
                                                        static_cast<std::size_t>(n));

                if (c.transport == Transport::kWs && !c.ws_upgraded) {
                    // Still in handshake phase.
                    auto st = c.ws_handshake.feed(incoming);
                    if (st == fb::net::ws::HandshakeParser::Status::kRejected) {
                        std::fprintf(stderr, "[server] ws handshake rejected: %s\n",
                                     c.ws_handshake.reason().c_str());
                        close_conn(fd);
                        return;
                    }
                    if (st == fb::net::ws::HandshakeParser::Status::kAccepted) {
                        const auto accept = fb::net::ws::compute_accept(
                            c.ws_handshake.client_key());
                        const auto resp = fb::net::ws::build_101_response(accept);
                        c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
                        loop.mod_fd(fd, EPOLLIN | EPOLLOUT | EPOLLET);
                        c.ws_upgraded = true;
                        // Forward any bytes that came in after the header
                        // terminator straight into the WS frame parser.
                        c.ws_parser.feed(c.ws_handshake.trailing());
                    }
                } else if (c.transport == Transport::kWs && c.ws_upgraded) {
                    c.ws_parser.feed(incoming);
                } else {
                    c.dec.feed(incoming);
                }

                // Drain whichever side is producing frames.
                if (c.transport == Transport::kWs && c.ws_upgraded) {
                    std::vector<std::uint8_t> msg;
                    fb::net::ws::FrameParser::PopStatus ws;
                    while ((ws = c.ws_parser.try_pop(msg)) ==
                           fb::net::ws::FrameParser::PopStatus::kFrameReady) {
                        // Each WS message is exactly one serialized FinBit Frame.
                        handle_frame(c, msg);
                        if (c.wants_close) { close_conn(fd); return; }
                    }
                    if (ws == fb::net::ws::FrameParser::PopStatus::kClose ||
                        ws == fb::net::ws::FrameParser::PopStatus::kError) {
                        close_conn(fd);
                        return;
                    }
                } else if (c.transport == Transport::kTcp) {
                    std::vector<std::uint8_t> frame;
                    fb::net::FrameDecoder::Status st;
                    while ((st = c.dec.try_pop(frame)) ==
                           fb::net::FrameDecoder::Status::kFrameReady) {
                        handle_frame(c, frame);
                        if (c.wants_close) { close_conn(fd); return; }
                    }
                    if (st == fb::net::FrameDecoder::Status::kError) {
                        close_conn(fd);
                        return;
                    }
                }
                // Used to break here if read_some returned fewer bytes
                // than requested — that's fine for plain TCP but
                // catastrophic for TLS, where OpenSSL may have more
                // application data already decrypted in its internal
                // buffer waiting for the next SSL_read. Loop until
                // read_some explicitly returns kReadRetry.
            }
        }
        if (events & EPOLLOUT) {
            while (!c.write_buf.empty()) {
                auto n = c.write_some(
                    std::span<const std::uint8_t>(c.write_buf.data(), c.write_buf.size()));
                if (n < 0) {
                    close_conn(fd);
                    return;
                }
                if (n == 0) break;
                c.write_buf.erase(c.write_buf.begin(), c.write_buf.begin() + n);
            }
            const std::uint32_t want = c.write_buf.empty() ? (EPOLLIN | EPOLLET)
                                                           : (EPOLLIN | EPOLLOUT | EPOLLET);
            loop.mod_fd(fd, want);
        }
    };

#if FB_HAVE_OPENSSL
    // SSL_CTX is shared across every TLS connection. Lifetime: the
    // duration of the process. SSL_CTX_free runs at scope exit via the
    // unique_ptr deleter.
    struct SslCtxDeleter { void operator()(SSL_CTX* p) const { if (p) SSL_CTX_free(p); } };
    std::unique_ptr<SSL_CTX, SslCtxDeleter> ssl_ctx;
    if (tls_port != 0 || tls_raw_port != 0) {
        if (tls_cert.empty() || tls_key.empty()) {
            std::fprintf(stderr,
                "[server] --tls-port / --tls-raw-port require "
                "both --tls-cert and --tls-key\n");
            return 1;
        }
        SSL_library_init();
        SSL_load_error_strings();
        ssl_ctx.reset(SSL_CTX_new(TLS_server_method()));
        if (!ssl_ctx) {
            std::fprintf(stderr, "[server] SSL_CTX_new failed\n");
            return 1;
        }
        // Modern defaults: TLS 1.2 minimum, no compression (CRIME),
        // no session ticket (we don't keep state across restarts).
        SSL_CTX_set_min_proto_version(ssl_ctx.get(), TLS1_2_VERSION);
        SSL_CTX_set_options(ssl_ctx.get(),
            SSL_OP_NO_COMPRESSION |
            SSL_OP_NO_TICKET |
            SSL_OP_CIPHER_SERVER_PREFERENCE);
        if (SSL_CTX_use_certificate_chain_file(ssl_ctx.get(), tls_cert.c_str()) != 1) {
            std::fprintf(stderr, "[server] could not load --tls-cert %s\n",
                         tls_cert.c_str());
            ERR_print_errors_fp(stderr);
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), tls_key.c_str(),
                                         SSL_FILETYPE_PEM) != 1) {
            std::fprintf(stderr, "[server] could not load --tls-key %s\n",
                         tls_key.c_str());
            ERR_print_errors_fp(stderr);
            return 1;
        }
        if (SSL_CTX_check_private_key(ssl_ctx.get()) != 1) {
            std::fprintf(stderr, "[server] --tls-cert / --tls-key mismatch\n");
            return 1;
        }
    }
#else
    if (tls_port != 0 || tls_raw_port != 0) {
        std::fprintf(stderr,
            "[server] this build was compiled without OpenSSL — "
            "--tls-port / --tls-raw-port ignored\n");
        tls_port = 0;
        tls_raw_port = 0;
    }
#endif

    auto accept_loop = [&](int lfd, Transport tx, bool tls_wrap) {
        for (;;) {
            auto s = fb::net::tcp_accept(lfd);
            if (!s.valid()) break;
            int fd = s.fd();
            auto c = std::make_unique<Conn>();
            c->sock = std::move(s);
            c->transport = tx;
#if FB_HAVE_OPENSSL
            if (tls_wrap && ssl_ctx) {
                c->ssl = SSL_new(ssl_ctx.get());
                SSL_set_fd(c->ssl, fd);
                SSL_set_accept_state(c->ssl);   // server-side handshake
            }
#else
            (void)tls_wrap;
#endif
            conns.emplace(fd, std::move(c));
            loop.add_fd(fd, EPOLLIN | EPOLLET, on_conn_ready);
            std::fprintf(stderr, "[server] accepted fd=%d transport=%s%s\n", fd,
                         tx == Transport::kWs ? "ws" : "tcp",
                         tls_wrap ? "+tls" : "");
        }
    };

    loop.add_fd(listener.fd(), EPOLLIN,
                [&](int lfd, std::uint32_t) { accept_loop(lfd, Transport::kTcp, /*tls=*/false); });

    std::optional<fb::net::Socket> ws_listener;
    if (ws_port != 0) {
        ws_listener = fb::net::tcp_listen(bind_host, ws_port);
        loop.add_fd(ws_listener->fd(), EPOLLIN,
                    [&](int lfd, std::uint32_t) { accept_loop(lfd, Transport::kWs, /*tls=*/false); });
        std::fprintf(stderr, "[server] WS listening on %s:%u\n", bind_host.c_str(),
                     static_cast<unsigned>(ws_port));
    }

    std::optional<fb::net::Socket> tls_listener;
    if (tls_port != 0) {
        tls_listener = fb::net::tcp_listen(bind_host, tls_port);
        loop.add_fd(tls_listener->fd(), EPOLLIN,
                    [&](int lfd, std::uint32_t) { accept_loop(lfd, Transport::kWs, /*tls=*/true); });
        std::fprintf(stderr, "[server] WSS listening on %s:%u (TLS)\n",
                     bind_host.c_str(), static_cast<unsigned>(tls_port));
    }

    // TLS-wrapped raw frames. Same wire format the --port listener
    // serves (length-prefixed Frame protobufs), just with a TLS layer
    // below. Lets native clients run on a likely-open port like 443
    // and look like HTTPS traffic to a passive observer.
    std::optional<fb::net::Socket> tls_raw_listener;
    if (tls_raw_port != 0) {
        if (tls_cert.empty() || tls_key.empty()) {
            std::fprintf(stderr,
                "[server] --tls-raw-port requires --tls-cert and --tls-key\n");
            return 2;
        }
        tls_raw_listener = fb::net::tcp_listen(bind_host, tls_raw_port);
        loop.add_fd(tls_raw_listener->fd(), EPOLLIN,
                    [&](int lfd, std::uint32_t) { accept_loop(lfd, Transport::kTcp, /*tls=*/true); });
        std::fprintf(stderr, "[server] TLS-RAW listening on %s:%u (TLS, native clients)\n",
                     bind_host.c_str(), static_cast<unsigned>(tls_raw_port));
    }

    std::fprintf(stderr, "[server] TCP listening on %s:%u\n", bind_host.c_str(),
                 static_cast<unsigned>(port));

    // When bound to all interfaces, print every external address with the
    // actual ports so the operator can copy/paste a connection URL.
    if (bind_host == "0.0.0.0") {
        const auto addrs = external_addresses();
        if (addrs.empty()) {
            std::fprintf(stderr,
                "[server] (no non-loopback interfaces detected — clients on this\n"
                "         host can still connect via 127.0.0.1)\n");
        } else {
            std::fprintf(stderr, "[server] reachable at:\n");
            for (const auto& a : addrs) {
                std::fprintf(stderr, "         tcp:  %s:%u\n", a.c_str(),
                             static_cast<unsigned>(port));
                if (ws_port != 0) {
                    std::fprintf(stderr, "         ws:   ws://%s:%u\n", a.c_str(),
                                 static_cast<unsigned>(ws_port));
                }
            }
            if (ws_port != 0) {
                std::fprintf(stderr,
                    "[server] NOTE: browsers refuse ws:// from https:// pages — for\n"
                    "         a public deployment, terminate TLS in a reverse proxy\n"
                    "         (caddy / nginx) and proxy wss:// to the ws-port above.\n");
            }
        }
    }

    // Periodic shutdown poll (epoll_wait blocks indefinitely).
    auto reschedule_stop_check = std::make_shared<std::function<void()>>();
    *reschedule_stop_check = [&]() {
        if (!g_run) loop.stop();
        loop.schedule(std::chrono::milliseconds(200), *reschedule_stop_check);
    };
    (*reschedule_stop_check)();

    loop.run();
    std::fprintf(stderr, "[server] shutting down\n");
    return 0;
}
