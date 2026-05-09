// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/mls_facade.hpp"

#include <stdexcept>
#include <string>

// =============================================================================
// MLS facade.
//
// Two builds compiled from this file:
//
//   FB_HAVE_MLS=0 (default) — every MlsGroup method throws "not implemented".
//   The repo still builds without mlspp, SenderKeys remains the only
//   channel cipher, and the type exists so consumers can compile against
//   the interface unconditionally.
//
//   FB_HAVE_MLS=1 — vendored mlspp under third_party/mlspp/ provides the
//   real implementation. Enable via cmake -DFB_FEATURE_MLS=ON. mls_facade
//   wraps mls::Session (the high-level wrapper around mls::State); the
//   wrapper hides every mlspp type behind a PIMPL so the public header
//   stays mlspp-clean and downstream code can compile without mlspp's
//   include path.
// =============================================================================

#if FB_HAVE_MLS

#include <mls/session.h>
#include <mls/credential.h>
#include <mls/crypto.h>

#include <memory>
#include <utility>

namespace fb::crypto {
namespace {

using namespace MLS_NAMESPACE;
using bytes_ns::bytes;

// MLS cipher suite that lines up with the rest of FinBit's stack:
// X25519 + AES-128-GCM + SHA-256 + Ed25519. AES-128 here is mlspp's
// default for this suite; FinBit's bulk AEAD uses AES-256-GCM at the
// envelope layer, so this is consistent with "standard primitives at
// every layer".
constexpr CipherSuite::ID kSuiteId =
    CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519;

bytes to_mls_bytes(std::span<const std::uint8_t> in) {
    // mls::bytes_ns::bytes only ships an std::vector<uint8_t>&& ctor —
    // no iterator-pair overload. Build a vector first, then move.
    std::vector<std::uint8_t> v(in.begin(), in.end());
    return bytes(std::move(v));
}

std::vector<std::uint8_t> from_mls_bytes(const bytes& in) {
    return std::vector<std::uint8_t>(in.begin(), in.end());
}

// Joiner-side wrapper around mls::Client + PendingJoin. Holds the
// generated mls::PendingJoin between key_package() publication and
// complete(welcome). Single-use; complete() moves the underlying
// state into the hydrated Session.
class PendingMlsJoinImpl final : public PendingMlsJoin {
public:
    PendingMlsJoinImpl(Client client, PendingJoin pending)
        : client_(std::move(client)), pending_(std::move(pending)) {}

    std::vector<std::uint8_t> key_package() const override {
        return from_mls_bytes(pending_.key_package());
    }

    std::unique_ptr<MlsGroup> complete(
        std::span<const std::uint8_t> welcome) override;

private:
    Client      client_;     // kept alive so the credential outlives the join
    PendingJoin pending_;
};

// PIMPL holding the live mlspp Session. Every MlsGroup method delegates
// here. The shape mirrors the public interface 1:1.
class MlsGroupImpl final : public MlsGroup {
public:
    explicit MlsGroupImpl(Session session) : session_(std::move(session)) {}

    AddResult add_member(std::span<const std::uint8_t> key_package) override {
        auto kp_bytes = to_mls_bytes(key_package);
        auto proposal = session_.add(kp_bytes);
        // mls::Session::commit returns (welcome, commit) in THAT order,
        // not (commit, welcome) — easy to get backwards.
        auto [welcome_b, commit_b] = session_.commit({proposal});
        // mls::Session caches the post-commit State in an internal
        // outbound_cache keyed by the commit bytes; nothing actually
        // advances our own epoch until we feed the commit back through
        // handle(). Without this our member_count() stays at the old
        // value and subsequent application_encrypt produces ciphertext
        // the new member can't decrypt.
        session_.handle(commit_b);
        AddResult r;
        r.welcome = from_mls_bytes(welcome_b);
        r.commit  = from_mls_bytes(commit_b);
        return r;
    }

    std::vector<std::uint8_t> remove_member(std::uint32_t leaf_index) override {
        auto proposal = session_.remove(leaf_index);
        auto [_welcome, commit_b] = session_.commit({proposal});
        session_.handle(commit_b);   // same self-apply as add_member
        return from_mls_bytes(commit_b);
    }

    std::vector<std::uint8_t> propose_add_member(
        std::span<const std::uint8_t> key_package) override {
        // Crucial subtlety: mls::Session::add ONLY returns wire-form
        // proposal bytes — it does NOT stage the proposal in OUR
        // local State. To stage we have to also handle() it
        // ourselves, exactly like every other member will do via
        // handle_proposal. Without this, commit_pending() commits
        // an empty epoch advance and the Welcome doesn't actually
        // include the new member — the joiner sees "Welcome not
        // intended for key package" on complete().
        auto proposal = session_.add(to_mls_bytes(key_package));
        session_.handle(proposal);
        return from_mls_bytes(proposal);
    }

    void handle_proposal(std::span<const std::uint8_t> proposal) override {
        // Session::handle on a Proposal stages it as pending. Idempotent
        // re-application is safe — mlspp dedups by proposal hash inside
        // the State.
        session_.handle(to_mls_bytes(proposal));
    }

    AddResult commit_pending() override {
        // Plain commit() bundles every staged proposal we and other
        // members have submitted into one Commit + Welcome. We
        // self-handle the Commit so our own epoch advances; the
        // returned bytes go to OTHER existing members (who handle()
        // them in turn) and to the Welcome's recipients.
        auto [welcome_b, commit_b] = session_.commit();
        session_.handle(commit_b);
        AddResult r;
        r.welcome = from_mls_bytes(welcome_b);
        r.commit  = from_mls_bytes(commit_b);
        return r;
    }

    std::vector<std::uint8_t> application_encrypt(
        std::span<const std::uint8_t> plaintext) override {
        return from_mls_bytes(session_.protect(to_mls_bytes(plaintext)));
    }

    std::optional<std::vector<std::uint8_t>> application_decrypt(
        std::span<const std::uint8_t> mls_msg) override {
        try {
            return from_mls_bytes(session_.unprotect(to_mls_bytes(mls_msg)));
        } catch (const std::exception&) {
            // mlspp raises on bad ciphertext / wrong epoch / unknown
            // sender. Map to a plain nullopt — every other crypto
            // primitive in the codebase uses that signal too.
            return std::nullopt;
        }
    }

    void apply_commit(std::span<const std::uint8_t> commit) override {
        session_.handle(to_mls_bytes(commit));
    }

    std::vector<std::uint8_t> serialize() const override {
        // Honest scope note: mlspp does not expose state persistence on
        // its public API. mls::Session keeps its history behind a PIMPL
        // and mls::State has no public tls::marshal — both decisions
        // are upstream design choices.
        //
        // The two viable paths to add persistence are:
        //   1. Patch mlspp to expose State (de)serialization. State has
        //      many internal invariants (chain keys, leaf indices, tree
        //      hashes) so the patch needs careful review.
        //   2. Build a transcript-replay layer here: save (sig_priv,
        //      init_priv, leaf_priv) at start_join, save the Welcome
        //      that hydrated us, and append every Commit we apply.
        //      On restore, reconstruct keys from saved bytes via
        //      HPKEPrivateKey::parse / SignaturePrivateKey::parse,
        //      build State via the join-from-Welcome constructor, then
        //      replay each Commit. Transcript stays bounded as long
        //      as members rotate periodically (each Commit produces a
        //      new epoch and old commits become reference material
        //      only).
        //
        // Neither fits in the v0 ship. ChatClient's restart path
        // recognises this — kMls channels whose cs.mls is null on
        // reload surface a "needs re-invite" signal rather than
        // crashing or pretending to be SenderKeys.
        throw std::runtime_error(
            "MlsGroup::serialize: persistence requires either patching "
            "mlspp to expose State (de)serialization or a transcript-"
            "replay layer above MlsGroup. Neither is wired in v0; "
            "channel survives within a session and needs re-invite "
            "after restart. See security-audit.md §10.");
    }

    std::size_t member_count() const override {
        // mls::Session::roster returns the leaf-node list for the
        // current epoch.
        return session_.roster().size();
    }

    std::vector<std::vector<std::uint8_t>> member_identities() const override {
        std::vector<std::vector<std::uint8_t>> out;
        for (const auto& leaf : session_.roster()) {
            // Each leaf carries a Credential. We only handle BasicCredential
            // (the one we use everywhere — the variant carries the
            // raw identity bytes we passed at create / start_join).
            // Other credential types (X.509, etc.) would surface here as
            // empty entries; mlspp throws on get_basic for non-basic
            // credentials, so swallow the throw.
            try {
                const auto& bc = leaf.credential.get<BasicCredential>();
                out.push_back(std::vector<std::uint8_t>(
                    bc.identity.begin(), bc.identity.end()));
            } catch (...) {
                out.emplace_back();   // unknown credential type
            }
        }
        return out;
    }

private:
    // mls::Session is move-only and holds an internal PIMPL. Wrap it
    // by value so RAII handles cleanup at MlsGroup destruction.
    Session session_;
};

}  // namespace

std::unique_ptr<MlsGroup> PendingMlsJoinImpl::complete(
    std::span<const std::uint8_t> welcome) {
    auto session = pending_.complete(to_mls_bytes(welcome));
    return std::make_unique<MlsGroupImpl>(std::move(session));
}

std::unique_ptr<MlsGroup> MlsGroup::create(
    std::span<const std::uint8_t, 32> creator_identity,
    std::span<const std::uint8_t, 32> group_id) {
    // Build a Client (= identity + cipher suite + credential), then ask
    // it to start a fresh group with the caller-chosen group_id. The
    // signature key is generated fresh per call — FinBit's identity
    // key is Ed25519, but mlspp owns its own MLS-namespaced keypair
    // for protocol hygiene; the facade's `creator_identity` becomes
    // the BasicCredential bytes (so the on-the-wire MLS member tag
    // points back at the right FinBit user).
    const auto suite = CipherSuite{ kSuiteId };
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred = Credential::basic(to_mls_bytes(creator_identity));
    Client client(suite, sig_priv, cred);
    auto session = client.begin_session(to_mls_bytes(group_id));
    return std::make_unique<MlsGroupImpl>(std::move(session));
}

std::unique_ptr<MlsGroup> MlsGroup::from_blob(std::span<const std::uint8_t>) {
    // Same gating as serialize() — needs TLS-syntax marshalling on
    // the mls::State path. Skipped for the v0 wrapper.
    throw std::runtime_error(
        "MlsGroup::from_blob: at-rest restore not yet wired");
}

std::unique_ptr<PendingMlsJoin> MlsGroup::start_join(
    std::span<const std::uint8_t, 32> joiner_identity) {
    const auto suite = CipherSuite{ kSuiteId };
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred = Credential::basic(to_mls_bytes(joiner_identity));
    Client client(suite, sig_priv, cred);
    auto pending = client.start_join();
    return std::make_unique<PendingMlsJoinImpl>(std::move(client),
                                                 std::move(pending));
}

}  // namespace fb::crypto

#else  // FB_HAVE_MLS == 0

namespace fb::crypto {
namespace {
[[noreturn]] void unimpl(const char* what) {
    throw std::runtime_error(std::string("MlsGroup: ") + what +
                             " not implemented (build with cmake "
                             "-DFB_FEATURE_MLS=ON to enable)");
}
}  // namespace

std::unique_ptr<MlsGroup> MlsGroup::create(std::span<const std::uint8_t, 32>,
                                            std::span<const std::uint8_t, 32>) {
    unimpl("create");
}

std::unique_ptr<MlsGroup> MlsGroup::from_blob(std::span<const std::uint8_t>) {
    unimpl("from_blob");
}

std::unique_ptr<PendingMlsJoin> MlsGroup::start_join(
    std::span<const std::uint8_t, 32>) {
    unimpl("start_join");
}

}  // namespace fb::crypto

// In FB_HAVE_MLS=0 builds the facade methods all throw, but the pure-
// virtual interface still has to compile against any consumer that
// includes the header. The concrete MlsGroupImpl only exists in the
// FB_HAVE_MLS=1 branch above; consumers that try to call methods on
// a stub MlsGroup will hit pure-virtual calls only if they
// successfully construct one — and create() / start_join() / from_blob
// already throw before any concrete object is constructed, so this
// is unreachable.

#endif  // FB_HAVE_MLS
