// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
// PeerNet gtests.
//
// Two PeerNet instances bound to localhost on different ports,
// each acting as both listener and dialer. Validates the
// direct-peer wire path without going through any central server.
//
// Cert generation: forks `openssl req` per fixture (skipped if openssl
// isn't on PATH — tests SKIP rather than FAIL in that case so CI
// environments without openssl don't get false negatives).
//
// Coverage:
//   - listener bound to 127.0.0.1 with auto-pick port; port query works
//   - send from A to B is delivered to B's on_message callback
//   - send back from B to A reuses an existing connection (or dials
//     the reverse direction; either is fine — both are wired)
//   - multi-message burst preserves ordering on a per-connection basis
//   - shutdown joins all worker threads cleanly
// =============================================================================

#include "fb/p2p/peer_net.hpp"
#include "fb/crypto/identity_cert.hpp"

#include <gtest/gtest.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if FB_HAVE_OPENSSL

namespace {

// Generate a self-signed cert for localhost via openssl(1). Skips
// the test if openssl isn't available.
struct CertPair {
    std::string cert_path;
    std::string key_path;
    bool        ok = false;
};

CertPair gen_cert(const std::string& tmpdir, int seq) {
    CertPair cp;
    cp.cert_path = tmpdir + "/cert" + std::to_string(seq) + ".pem";
    cp.key_path  = tmpdir + "/key"  + std::to_string(seq) + ".pem";
    std::string cmd =
        "openssl req -x509 -newkey rsa:2048 -nodes "
        "-keyout " + cp.key_path + " "
        "-out "    + cp.cert_path + " "
        "-days 1 -subj /CN=localhost "
        "-addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' "
        ">/dev/null 2>&1";
    cp.ok = (std::system(cmd.c_str()) == 0);
    return cp;
}

std::string make_tmpdir() {
    char tmpl[] = "/tmp/fb_peernet_XXXXXX";
    char* p = mkdtemp(tmpl);
    if (!p) return {};
    return p;
}

void rmrf(const std::string& d) {
    if (d.empty()) return;
    std::system(("rm -rf " + d).c_str());
}

// Wait for a condition with a deadline. Returns true if the
// condition fired before the deadline, false otherwise. Used to
// avoid hard sleeps in the asynchronous PeerNet tests.
template <class Pred>
bool wait_until(int timeout_ms, Pred&& p) {
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (p()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return p();
}

}  // namespace

TEST(PeerNet, ListenerBindsAndReportsPort) {
    auto tmpdir = make_tmpdir();
    if (tmpdir.empty()) GTEST_SKIP() << "could not create tmpdir";
    auto cp = gen_cert(tmpdir, 1);
    if (!cp.ok) {
        rmrf(tmpdir);
        GTEST_SKIP() << "openssl(1) not available; skipping cert-dep test";
    }

    fb::p2p::PeerNet net;
    fb::p2p::PeerListenerOptions opts;
    opts.bind_host    = "127.0.0.1";
    opts.bind_port    = 0;   // kernel-assigned
    opts.tls_cert_pem = cp.cert_path;
    opts.tls_key_pem  = cp.key_path;
    net.start_listener(opts);
    EXPECT_GT(net.listener_port(), 0);
    rmrf(tmpdir);
}

TEST(PeerNet, RoundTripBetweenTwoLoopbackInstances) {
    auto tmpdir = make_tmpdir();
    if (tmpdir.empty()) GTEST_SKIP() << "could not create tmpdir";
    auto cpA = gen_cert(tmpdir, 1);
    auto cpB = gen_cert(tmpdir, 2);
    if (!cpA.ok || !cpB.ok) {
        rmrf(tmpdir);
        GTEST_SKIP() << "openssl(1) not available";
    }

    fb::p2p::PeerNet a, b;

    // A's inbox.
    std::mutex a_mu;
    std::vector<std::vector<std::uint8_t>> a_inbox;
    a.set_on_message([&](const fb::p2p::PeerInfo&,
                          std::span<const std::uint8_t> bytes) {
        std::lock_guard lk(a_mu);
        a_inbox.emplace_back(bytes.begin(), bytes.end());
    });
    // B's inbox.
    std::mutex b_mu;
    std::vector<std::vector<std::uint8_t>> b_inbox;
    b.set_on_message([&](const fb::p2p::PeerInfo&,
                          std::span<const std::uint8_t> bytes) {
        std::lock_guard lk(b_mu);
        b_inbox.emplace_back(bytes.begin(), bytes.end());
    });

    // Both listen on auto-pick ports.
    fb::p2p::PeerListenerOptions a_lo;
    a_lo.bind_host    = "127.0.0.1";
    a_lo.tls_cert_pem = cpA.cert_path;
    a_lo.tls_key_pem  = cpA.key_path;
    a.start_listener(a_lo);

    fb::p2p::PeerListenerOptions b_lo;
    b_lo.bind_host    = "127.0.0.1";
    b_lo.tls_cert_pem = cpB.cert_path;
    b_lo.tls_key_pem  = cpB.key_path;
    b.start_listener(b_lo);

    // Self-signed certs → both sides need insecure_skip_verify (no
    // shared CA at test time).
    fb::p2p::PeerDialerOptions dopts;
    dopts.insecure_skip_verify = true;
    a.set_dialer(dopts);
    b.set_dialer(dopts);

    fb::p2p::PeerInfo b_target{};
    b_target.addr = "wss://127.0.0.1:" + std::to_string(b.listener_port());

    // A → B
    const std::vector<std::uint8_t> hello{'h', 'i', '!', 0x01, 0x02};
    EXPECT_TRUE(a.send(b_target,
        std::span<const std::uint8_t>(hello.data(), hello.size())));

    // B's on_message should fire within a few seconds (TLS handshake
    // typically <500ms on loopback).
    EXPECT_TRUE(wait_until(5000, [&]() {
        std::lock_guard lk(b_mu);
        return !b_inbox.empty();
    }));
    {
        std::lock_guard lk(b_mu);
        ASSERT_FALSE(b_inbox.empty());
        EXPECT_EQ(b_inbox.front(), hello);
    }

    // Reverse: B → A. Independent connection (B dials A).
    fb::p2p::PeerInfo a_target{};
    a_target.addr = "wss://127.0.0.1:" + std::to_string(a.listener_port());
    const std::vector<std::uint8_t> reply{'a', 'c', 'k'};
    EXPECT_TRUE(b.send(a_target,
        std::span<const std::uint8_t>(reply.data(), reply.size())));
    EXPECT_TRUE(wait_until(5000, [&]() {
        std::lock_guard lk(a_mu);
        return !a_inbox.empty();
    }));
    {
        std::lock_guard lk(a_mu);
        ASSERT_FALSE(a_inbox.empty());
        EXPECT_EQ(a_inbox.front(), reply);
    }

    rmrf(tmpdir);
}

TEST(PeerNet, BurstSendsArriveInOrderOnSingleConnection) {
    auto tmpdir = make_tmpdir();
    if (tmpdir.empty()) GTEST_SKIP() << "could not create tmpdir";
    auto cp = gen_cert(tmpdir, 1);
    if (!cp.ok) {
        rmrf(tmpdir);
        GTEST_SKIP() << "openssl(1) not available";
    }
    fb::p2p::PeerNet a, b;

    std::mutex b_mu;
    std::vector<std::vector<std::uint8_t>> b_inbox;
    b.set_on_message([&](const fb::p2p::PeerInfo&,
                          std::span<const std::uint8_t> bytes) {
        std::lock_guard lk(b_mu);
        b_inbox.emplace_back(bytes.begin(), bytes.end());
    });

    fb::p2p::PeerListenerOptions b_lo;
    b_lo.bind_host    = "127.0.0.1";
    b_lo.tls_cert_pem = cp.cert_path;
    b_lo.tls_key_pem  = cp.key_path;
    b.start_listener(b_lo);

    fb::p2p::PeerDialerOptions dopts;
    dopts.insecure_skip_verify = true;
    a.set_dialer(dopts);

    fb::p2p::PeerInfo b_target{};
    b_target.addr = "wss://127.0.0.1:" + std::to_string(b.listener_port());

    constexpr int kBurst = 8;
    for (int i = 0; i < kBurst; ++i) {
        std::vector<std::uint8_t> payload{static_cast<std::uint8_t>(i),
                                            static_cast<std::uint8_t>(i + 1)};
        EXPECT_TRUE(a.send(b_target,
            std::span<const std::uint8_t>(payload.data(), payload.size())));
    }

    EXPECT_TRUE(wait_until(8000, [&]() {
        std::lock_guard lk(b_mu);
        return b_inbox.size() == kBurst;
    }));
    {
        std::lock_guard lk(b_mu);
        ASSERT_EQ(b_inbox.size(), static_cast<std::size_t>(kBurst));
        for (int i = 0; i < kBurst; ++i) {
            ASSERT_EQ(b_inbox[i].size(), 2u);
            EXPECT_EQ(b_inbox[i][0], static_cast<std::uint8_t>(i));
            EXPECT_EQ(b_inbox[i][1], static_cast<std::uint8_t>(i + 1));
        }
    }
    // A reused one outbound connection for all 8 sends.
    EXPECT_EQ(a.outbound_count(), 1u);
    rmrf(tmpdir);
}

// Mutual-TLS: A and B both use IDENTITY-derived self-signed certs.
// Each side extracts the peer's pubkey from their cert and exposes
// it via on_message's PeerInfo.pubkey. A's send to B with an
// expected_peer_pubkey of B's identity succeeds; A's send to B
// with the WRONG expected_peer_pubkey fails (the dial throws
// "identity-pin failure" inside PeerNet's worker, so the bytes
// never reach B's on_message).
TEST(PeerNet, MutualTlsIdentityPinningSucceedsAndRejects) {
    auto tmpdir = make_tmpdir();
    if (tmpdir.empty()) GTEST_SKIP() << "could not create tmpdir";

    // Generate identity certs for A and B from distinct Ed25519 seeds.
    std::array<std::uint8_t, 32> seedA{}; seedA[0] = 0xa1;
    std::array<std::uint8_t, 32> seedB{}; seedB[0] = 0xb2;
    auto certA = fb::crypto::generate_identity_cert(
        std::span<const std::uint8_t, 32>(seedA));
    auto certB = fb::crypto::generate_identity_cert(
        std::span<const std::uint8_t, 32>(seedB));

    auto write = [&](const std::string& name, const std::string& contents) {
        const std::string path = tmpdir + "/" + name;
        std::ofstream o(path);
        o << contents;
        return path;
    };
    const auto a_cert_path = write("a_cert.pem", certA.cert_pem);
    const auto a_key_path  = write("a_key.pem",  certA.key_pem);
    const auto b_cert_path = write("b_cert.pem", certB.cert_pem);
    const auto b_key_path  = write("b_key.pem",  certB.key_pem);

    // Recover B's actual pubkey to use as the expected pin (and as
    // the wrong pin for the failure case, we'll use a random one).
    auto bpub = fb::crypto::extract_pubkey_from_cert_pem(certB.cert_pem);
    ASSERT_TRUE(bpub.has_value());

    fb::p2p::PeerNet a, b;

    std::mutex b_mu;
    std::vector<std::vector<std::uint8_t>> b_inbox;
    std::vector<std::vector<std::uint8_t>> b_inbox_pubs;
    b.set_on_message([&](const fb::p2p::PeerInfo& from,
                          std::span<const std::uint8_t> bytes) {
        std::lock_guard lk(b_mu);
        b_inbox.emplace_back(bytes.begin(), bytes.end());
        b_inbox_pubs.emplace_back(from.pubkey);
    });

    fb::p2p::PeerListenerOptions b_lo;
    b_lo.bind_host          = "127.0.0.1";
    b_lo.tls_cert_pem       = b_cert_path;
    b_lo.tls_key_pem        = b_key_path;
    b_lo.require_client_cert = true;   // mutual auth required
    b.start_listener(b_lo);

    fb::p2p::PeerListenerOptions a_lo;
    a_lo.bind_host          = "127.0.0.1";
    a_lo.tls_cert_pem       = a_cert_path;
    a_lo.tls_key_pem        = a_key_path;
    a_lo.require_client_cert = true;
    a.start_listener(a_lo);

    // Configure A's dialer with A's identity cert + key.
    fb::p2p::PeerDialerOptions dopts;
    dopts.client_cert_pem      = certA.cert_pem;
    dopts.client_key_pem       = certA.key_pem;
    dopts.insecure_skip_verify = true;
    a.set_dialer(dopts);

    // Happy path: A sends to B with B's CORRECT identity pubkey.
    fb::p2p::PeerInfo b_target{};
    b_target.addr = "wss://127.0.0.1:" + std::to_string(b.listener_port());
    b_target.pubkey.assign(bpub->begin(), bpub->end());
    const std::vector<std::uint8_t> hello{'h','i','!'};
    EXPECT_TRUE(a.send(b_target,
        std::span<const std::uint8_t>(hello.data(), hello.size())));

    EXPECT_TRUE(wait_until(5000, [&]() {
        std::lock_guard lk(b_mu);
        return !b_inbox.empty();
    }));

    // B saw A's IDENTITY pubkey on the connection (extracted from
    // A's mutual-TLS cert) — not a self-stamped sender_pubkey field.
    auto apub = fb::crypto::extract_pubkey_from_cert_pem(certA.cert_pem);
    ASSERT_TRUE(apub.has_value());
    {
        std::lock_guard lk(b_mu);
        ASSERT_FALSE(b_inbox_pubs.empty());
        EXPECT_EQ(b_inbox_pubs.front().size(), 32u);
        EXPECT_TRUE(std::equal(b_inbox_pubs.front().begin(),
                                b_inbox_pubs.front().end(),
                                apub->begin()));
    }

    // Mismatch path: A sends to B's address but expects a DIFFERENT
    // pubkey. The dial should throw "identity-pin failure" inside
    // PeerNet's worker, so B's on_message MUST NOT see the bytes.
    fb::p2p::PeerNet a2;
    a2.set_dialer(dopts);
    fb::p2p::PeerInfo bad_target{};
    bad_target.addr = "wss://127.0.0.1:" + std::to_string(b.listener_port());
    std::array<std::uint8_t, 32> wrong_pub{};
    for (auto& b8 : wrong_pub) b8 = 0xee;
    bad_target.pubkey.assign(wrong_pub.begin(), wrong_pub.end());

    const std::size_t before = ([&]() {
        std::lock_guard lk(b_mu);
        return b_inbox.size();
    })();
    const std::vector<std::uint8_t> nope{'n','o'};
    a2.send(bad_target,
        std::span<const std::uint8_t>(nope.data(), nope.size()));
    // Give the dial+handshake plenty of time to complete (or fail).
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    {
        std::lock_guard lk(b_mu);
        EXPECT_EQ(b_inbox.size(), before)
            << "B received bytes from a peer with mismatched pinned pubkey";
    }

    rmrf(tmpdir);
}

TEST(PeerNet, ShutdownJoinsCleanly) {
    auto tmpdir = make_tmpdir();
    if (tmpdir.empty()) GTEST_SKIP() << "could not create tmpdir";
    auto cp = gen_cert(tmpdir, 1);
    if (!cp.ok) {
        rmrf(tmpdir);
        GTEST_SKIP() << "openssl(1) not available";
    }
    {
        fb::p2p::PeerNet n;
        fb::p2p::PeerListenerOptions opts;
        opts.bind_host    = "127.0.0.1";
        opts.tls_cert_pem = cp.cert_path;
        opts.tls_key_pem  = cp.key_path;
        n.start_listener(opts);
        // Just exercising the destructor — a leaked thread or
        // never-released SSL_CTX would surface as a hang or ASAN
        // hit.
    }
    rmrf(tmpdir);
}

#else  // FB_HAVE_OPENSSL == 0

TEST(PeerNet, StubBuildThrows) {
    fb::p2p::PeerNet n;
    EXPECT_THROW({
        fb::p2p::PeerListenerOptions o;
        o.tls_cert_pem = "/dev/null";
        o.tls_key_pem  = "/dev/null";
        n.start_listener(o);
    }, std::runtime_error);
}

#endif
