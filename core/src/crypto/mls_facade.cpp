// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/mls_facade.hpp"

#include <stdexcept>
#include <string>

// =============================================================================
// MLS facade — State-backed implementation with at-rest persistence.
//
// The Phase-1 wrapper used mls::Session, which hides its underlying
// mls::State behind a PIMPL and exposes no marshalling. That made
// persistence impossible without either patching mlspp or building a
// transcript-replay layer above MlsGroup. This file is that layer.
//
// Approach: bypass mls::Session/Client/PendingJoin entirely and use
// mls::State directly. State accepts explicit (init_priv, leaf_priv,
// sig_priv, ...) at construction, so we can generate those keys
// ourselves, hold them across the lifetime of MlsGroup, and serialize
// them in the seed blob. Combined with an append-only log of every
// Commit we apply, this is enough to deterministically reconstruct
// the State on restart by:
//
//   1. parse keys via SignaturePrivateKey::parse / HPKEPrivateKey::parse
//   2. invoke the same State constructor used at create or join time
//   3. for each saved Commit, call state.handle(MLSMessage commit) and
//      replace state with the returned new state
//
// Two builds compiled from this file:
//
//   FB_HAVE_MLS=0 (default) — every MlsGroup method throws "not
//     implemented". The repo still builds without mlspp.
//
//   FB_HAVE_MLS=1 — vendored mlspp under third_party/mlspp/ provides
//     the real implementation. Enable via cmake -DFB_FEATURE_MLS=ON.
// =============================================================================

#if FB_HAVE_MLS

#include <mls/credential.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/state.h>
#include <tls/tls_syntax.h>

#include <memory>
#include <utility>

namespace fb::crypto {
namespace {

using namespace MLS_NAMESPACE;
using bytes_ns::bytes;

// MLS cipher suite that lines up with the rest of FinBit's stack:
// X25519 + AES-128-GCM + SHA-256 + Ed25519. AES-128 here is mlspp's
// default for this suite; FinBit's bulk AEAD uses AES-256-GCM at the
// envelope layer.
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

// -----------------------------------------------------------------------------
// Seed-blob binary format (v1).
//
// Single contiguous blob written ONCE per MlsGroup at create or
// Welcome-complete. Keys + identity + bootstrap inputs only — never
// any State internals (we don't have access to those). Commits are
// stored separately and replayed on restore.
//
// Wire layout (little-endian throughout — same convention as the
// rest of FinBit's binary scratch):
//
//   uint8   version              = 1
//   uint8   role                 (0 = creator, 1 = joiner)
//   uint8   cipher_suite_id      (1 = X25519_AES128GCM_SHA256_Ed25519)
//   uint8   reserved             = 0
//   uint16  group_id_len
//   bytes   group_id
//   uint16  identity_len
//   bytes   identity
//   uint32  sig_priv_len
//   bytes   sig_priv             (SignaturePrivateKey::data)
//   uint32  leaf_priv_len
//   bytes   leaf_priv            (HPKEPrivateKey::data)
//   uint32  init_priv_len        (0 if creator)
//   bytes   init_priv            (HPKEPrivateKey::data, joiner only)
//   uint32  key_package_len      (0 if creator)
//   bytes   key_package          (tls::marshal(KeyPackage), joiner only)
//   uint32  welcome_len          (0 if creator)
//   bytes   welcome              (tls::marshal(Welcome), joiner only)
//   uint32  creator_init_secret_len   (0 if joiner)
//   bytes   creator_init_secret  (the random init_secret captured
//                                 at empty-group construction; needs
//                                 the FinBit mlspp patch that
//                                 exposes State::init_secret_value()
//                                 and the override-init-secret ctor)
//   uint32  creator_leaf_node_len     (0 if joiner)
//   bytes   creator_leaf_node    (tls::marshal of the LeafNode used
//                                 at create time. Must be saved
//                                 because LeafNode embeds Lifetime
//                                 (current time at construction) +
//                                 Capabilities — without preserving
//                                 the exact bytes, the rebuilt
//                                 leaf_node hashes differently and
//                                 the resulting KeyScheduleEpoch
//                                 ctx differs.)
//
// For the creator role we still emit the 0-length init/kp/welcome
// fields so the decoder can be format-agnostic.
// -----------------------------------------------------------------------------

constexpr std::uint8_t kSeedVersion = 1;

enum SeedRole : std::uint8_t { kRoleCreator = 0, kRoleJoiner = 1 };

void put_u8(std::vector<std::uint8_t>& out, std::uint8_t v) {
    out.push_back(v);
}
void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
}
void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
}
void put_bytes(std::vector<std::uint8_t>& out, const bytes& v) {
    out.insert(out.end(), v.begin(), v.end());
}

class Reader {
public:
    Reader(std::span<const std::uint8_t> in) : data_(in), pos_(0) {}

    std::uint8_t u8() {
        require(1);
        return data_[pos_++];
    }
    std::uint16_t u16() {
        require(2);
        std::uint16_t v = static_cast<std::uint16_t>(data_[pos_]) |
                          (static_cast<std::uint16_t>(data_[pos_ + 1]) << 8);
        pos_ += 2;
        return v;
    }
    std::uint32_t u32() {
        require(4);
        std::uint32_t v =
            static_cast<std::uint32_t>(data_[pos_]) |
            (static_cast<std::uint32_t>(data_[pos_ + 1]) << 8) |
            (static_cast<std::uint32_t>(data_[pos_ + 2]) << 16) |
            (static_cast<std::uint32_t>(data_[pos_ + 3]) << 24);
        pos_ += 4;
        return v;
    }
    std::vector<std::uint8_t> take(std::size_t n) {
        require(n);
        std::vector<std::uint8_t> out(data_.begin() + pos_,
                                       data_.begin() + pos_ + n);
        pos_ += n;
        return out;
    }
    bool eof() const { return pos_ >= data_.size(); }

private:
    void require(std::size_t n) {
        if (pos_ + n > data_.size()) {
            throw std::runtime_error(
                "MlsGroup: truncated seed/log blob during decode");
        }
    }
    std::span<const std::uint8_t> data_;
    std::size_t pos_;
};

// -----------------------------------------------------------------------------
// Operation log — encode/decode helpers.
//
// Each entry in the log captures one state-mutating effect plus the
// inputs we used. On replay we re-execute the same effect against the
// rebuilt State; if every input is preserved (including any random
// leaf_secret), the resulting State is byte-equivalent to the live
// one. This sidesteps mlspp's "Handle own commits with caching" check
// that blocks naive wire-form commit replay.
//
// Op record layout (little-endian):
//   uint8   op_kind
//   uint32  payload_len
//   bytes   payload          (per-kind layout below)
//
// Kinds:
//   1  ADD_MEMBER       payload: u32 kp_len, kp_bytes,
//                                u32 leaf_secret_len, leaf_secret
//   2  REMOVE_MEMBER    payload: u32 leaf_idx,
//                                u32 leaf_secret_len, leaf_secret
//   3  PROPOSE_ADD      payload: u32 kp_len, kp_bytes
//   4  HANDLE_PROPOSAL  payload: u32 wire_len, wire_bytes
//   5  COMMIT_PENDING   payload: u32 leaf_secret_len, leaf_secret
//   6  APPLY_COMMIT     payload: u32 wire_len, wire_bytes
// -----------------------------------------------------------------------------

enum OpKind : std::uint8_t {
    kOpAddMember      = 1,
    kOpRemoveMember   = 2,
    kOpProposeAdd     = 3,
    kOpHandleProposal = 4,
    kOpCommitPending  = 5,
    kOpApplyCommit    = 6,
};

std::vector<std::uint8_t> encode_op_addmember(const bytes& kp,
                                               const bytes& leaf_secret) {
    std::vector<std::uint8_t> p;
    put_u32(p, static_cast<std::uint32_t>(kp.size()));
    put_bytes(p, kp);
    put_u32(p, static_cast<std::uint32_t>(leaf_secret.size()));
    put_bytes(p, leaf_secret);
    std::vector<std::uint8_t> out;
    put_u8(out, kOpAddMember);
    put_u32(out, static_cast<std::uint32_t>(p.size()));
    out.insert(out.end(), p.begin(), p.end());
    return out;
}

std::vector<std::uint8_t> encode_op_removemember(std::uint32_t leaf_idx,
                                                  const bytes& leaf_secret) {
    std::vector<std::uint8_t> p;
    put_u32(p, leaf_idx);
    put_u32(p, static_cast<std::uint32_t>(leaf_secret.size()));
    put_bytes(p, leaf_secret);
    std::vector<std::uint8_t> out;
    put_u8(out, kOpRemoveMember);
    put_u32(out, static_cast<std::uint32_t>(p.size()));
    out.insert(out.end(), p.begin(), p.end());
    return out;
}

std::vector<std::uint8_t> encode_op_proposeadd(const bytes& kp) {
    std::vector<std::uint8_t> p;
    put_u32(p, static_cast<std::uint32_t>(kp.size()));
    put_bytes(p, kp);
    std::vector<std::uint8_t> out;
    put_u8(out, kOpProposeAdd);
    put_u32(out, static_cast<std::uint32_t>(p.size()));
    out.insert(out.end(), p.begin(), p.end());
    return out;
}

std::vector<std::uint8_t> encode_op_wire(OpKind kind, const bytes& wire) {
    std::vector<std::uint8_t> p;
    put_u32(p, static_cast<std::uint32_t>(wire.size()));
    put_bytes(p, wire);
    std::vector<std::uint8_t> out;
    put_u8(out, static_cast<std::uint8_t>(kind));
    put_u32(out, static_cast<std::uint32_t>(p.size()));
    out.insert(out.end(), p.begin(), p.end());
    return out;
}

std::vector<std::uint8_t> encode_op_commitpending(const bytes& leaf_secret) {
    std::vector<std::uint8_t> p;
    put_u32(p, static_cast<std::uint32_t>(leaf_secret.size()));
    put_bytes(p, leaf_secret);
    std::vector<std::uint8_t> out;
    put_u8(out, kOpCommitPending);
    put_u32(out, static_cast<std::uint32_t>(p.size()));
    out.insert(out.end(), p.begin(), p.end());
    return out;
}

// -----------------------------------------------------------------------------
// Helper: build a fresh KeyPackage + LeafNode for a joiner from already-
// generated keys. Replicates what mls::PendingJoin::Inner does
// internally, but with the keys exposed to us so we can persist them.
// -----------------------------------------------------------------------------
struct JoinerKeys {
    HPKEPrivateKey       init_priv;
    HPKEPrivateKey       leaf_priv;
    SignaturePrivateKey  sig_priv;
    KeyPackage           key_package;
};

JoinerKeys build_joiner_keys(CipherSuite suite,
                              SignaturePrivateKey sig_priv,
                              Credential cred) {
    auto init_priv = HPKEPrivateKey::generate(suite);
    auto leaf_priv = HPKEPrivateKey::generate(suite);
    auto leaf_node = LeafNode(suite,
                              leaf_priv.public_key,
                              sig_priv.public_key,
                              std::move(cred),
                              Capabilities::create_default(),
                              Lifetime::create_default(),
                              {},
                              sig_priv);
    auto kp = KeyPackage(suite,
                         init_priv.public_key,
                         leaf_node,
                         {},
                         sig_priv);
    return JoinerKeys{
        std::move(init_priv),
        std::move(leaf_priv),
        std::move(sig_priv),
        std::move(kp),
    };
}

// -----------------------------------------------------------------------------
// State-backed MlsGroup. Owns the live State, the keys we generated
// at bootstrap, the seed blob (so we can re-emit it at any moment
// without recomputing), and the ordered commit log.
// -----------------------------------------------------------------------------
class MlsGroupImpl final : public MlsGroup {
public:
    // Constructor for the creator path: seed_blob is the already-built
    // bootstrap bytes for our role. state is the live State the caller
    // produced via the empty-group constructor.
    MlsGroupImpl(State state,
                 SignaturePrivateKey sig_priv,
                 HPKEPrivateKey leaf_priv,
                 std::vector<std::uint8_t> seed_blob)
        : state_(std::move(state))
        , sig_priv_(std::move(sig_priv))
        , leaf_priv_(std::move(leaf_priv))
        , seed_blob_(std::move(seed_blob))
    {}

    // Constructor for the restored path: state was built from seed via
    // the join-from-Welcome constructor (or empty-group constructor),
    // then ops replayed. Seed blob is the bytes we just consumed.
    MlsGroupImpl(State state,
                 SignaturePrivateKey sig_priv,
                 HPKEPrivateKey leaf_priv,
                 std::vector<std::uint8_t> seed_blob,
                 std::vector<std::vector<std::uint8_t>> op_log)
        : state_(std::move(state))
        , sig_priv_(std::move(sig_priv))
        , leaf_priv_(std::move(leaf_priv))
        , seed_blob_(std::move(seed_blob))
        , op_log_(std::move(op_log))
    {}

    AddResult add_member(std::span<const std::uint8_t> key_package) override {
        auto kp_b = to_mls_bytes(key_package);
        auto leaf_secret = random_leaf_secret();
        auto r = do_add_member(kp_b, leaf_secret);
        op_log_.push_back(encode_op_addmember(kp_b, leaf_secret));
        return r;
    }

    std::vector<std::uint8_t> remove_member(std::uint32_t leaf_index) override {
        auto leaf_secret = random_leaf_secret();
        auto wire = do_remove_member(leaf_index, leaf_secret);
        op_log_.push_back(encode_op_removemember(leaf_index, leaf_secret));
        return wire;
    }

    std::vector<std::uint8_t> propose_add_member(
        std::span<const std::uint8_t> key_package) override {
        auto kp_b = to_mls_bytes(key_package);
        auto wire = do_propose_add_member(kp_b);
        op_log_.push_back(encode_op_proposeadd(kp_b));
        return wire;
    }

    void handle_proposal(std::span<const std::uint8_t> proposal) override {
        auto wire_b = to_mls_bytes(proposal);
        do_handle_proposal(wire_b);
        op_log_.push_back(encode_op_wire(kOpHandleProposal, wire_b));
    }

    AddResult commit_pending() override {
        auto leaf_secret = random_leaf_secret();
        auto r = do_commit_pending(leaf_secret);
        op_log_.push_back(encode_op_commitpending(leaf_secret));
        return r;
    }

    std::vector<std::uint8_t> application_encrypt(
        std::span<const std::uint8_t> plaintext) override {
        auto msg = state_.protect({}, to_mls_bytes(plaintext), /*pad=*/0);
        return from_mls_bytes(tls::marshal(msg));
    }

    std::optional<std::vector<std::uint8_t>> application_decrypt(
        std::span<const std::uint8_t> mls_msg) override {
        try {
            auto msg = tls::get<MLSMessage>(to_mls_bytes(mls_msg));
            auto [_aad, pt] = state_.unprotect(msg);
            return from_mls_bytes(pt);
        } catch (const std::exception&) {
            // Bad ciphertext, wrong epoch, unknown sender, malformed
            // wire bytes — all surface as nullopt (matches every other
            // crypto primitive in FinBit).
            return std::nullopt;
        }
    }

    void apply_commit(std::span<const std::uint8_t> commit) override {
        auto wire_b = to_mls_bytes(commit);
        do_apply_commit(wire_b);
        op_log_.push_back(encode_op_wire(kOpApplyCommit, wire_b));
    }

    std::vector<std::uint8_t> serialize_seed() const override {
        return seed_blob_;
    }

    std::vector<std::vector<std::uint8_t>> operation_log() const override {
        return op_log_;
    }

    std::vector<std::uint8_t> serialize() const override {
        // Convenience bundle: seed length-prefixed, then op count
        // length-prefixed ops. Format version 1, magic "MGB1".
        std::vector<std::uint8_t> out;
        out.reserve(8 + seed_blob_.size() + 4 +
                    op_log_.size() * 256);
        out.push_back('M');
        out.push_back('G');
        out.push_back('B');
        out.push_back('1');
        put_u32(out, static_cast<std::uint32_t>(seed_blob_.size()));
        out.insert(out.end(), seed_blob_.begin(), seed_blob_.end());
        put_u32(out, static_cast<std::uint32_t>(op_log_.size()));
        for (const auto& op : op_log_) {
            put_u32(out, static_cast<std::uint32_t>(op.size()));
            out.insert(out.end(), op.begin(), op.end());
        }
        return out;
    }

    std::size_t member_count() const override {
        return state_.roster().size();
    }

    std::vector<std::vector<std::uint8_t>> member_identities() const override {
        std::vector<std::vector<std::uint8_t>> out;
        for (const auto& leaf : state_.roster()) {
            try {
                const auto& bc = leaf.credential.get<BasicCredential>();
                out.push_back(std::vector<std::uint8_t>(
                    bc.identity.begin(), bc.identity.end()));
            } catch (...) {
                out.emplace_back();
            }
        }
        return out;
    }

    // Public replay entry point — used by from_seed_and_log to feed
    // saved op records back through the same code paths the live
    // mutators used. Inputs are the SAME as the original mutator, so
    // the resulting State is byte-equivalent to the live one.
    void replay_op(std::span<const std::uint8_t> op_bytes) {
        Reader r(op_bytes);
        auto kind = r.u8();
        auto plen = r.u32();
        auto payload_vec = r.take(plen);
        Reader p(std::span<const std::uint8_t>(
            payload_vec.data(), payload_vec.size()));
        switch (kind) {
            case kOpAddMember: {
                auto kp_len = p.u32();
                auto kp = p.take(kp_len);
                auto ls_len = p.u32();
                auto ls = p.take(ls_len);
                (void)do_add_member(bytes(std::move(kp)),
                                     bytes(std::move(ls)));
                break;
            }
            case kOpRemoveMember: {
                auto idx = p.u32();
                auto ls_len = p.u32();
                auto ls = p.take(ls_len);
                (void)do_remove_member(idx, bytes(std::move(ls)));
                break;
            }
            case kOpProposeAdd: {
                auto kp_len = p.u32();
                auto kp = p.take(kp_len);
                (void)do_propose_add_member(bytes(std::move(kp)));
                break;
            }
            case kOpHandleProposal: {
                auto wlen = p.u32();
                auto w = p.take(wlen);
                do_handle_proposal(bytes(std::move(w)));
                break;
            }
            case kOpCommitPending: {
                auto ls_len = p.u32();
                auto ls = p.take(ls_len);
                (void)do_commit_pending(bytes(std::move(ls)));
                break;
            }
            case kOpApplyCommit: {
                auto wlen = p.u32();
                auto w = p.take(wlen);
                do_apply_commit(bytes(std::move(w)));
                break;
            }
            default:
                throw std::runtime_error(
                    "MlsGroup: replay_op unknown kind " +
                    std::to_string(kind));
        }
        // Append to op_log_ so a SECOND serialize_seed/operation_log
        // round trip from the restored group is valid.
        op_log_.push_back(
            std::vector<std::uint8_t>(op_bytes.begin(), op_bytes.end()));
    }

private:
    bytes random_leaf_secret() const {
        // mlspp picks a fresh ephemeral leaf secret per commit; size
        // is the cipher suite's secret_size (32 bytes for SHA-256).
        return random_bytes(state_.cipher_suite().secret_size());
    }

    // Internal: do the work of add_member without recording an op.
    // Used by both the live mutator (which then records) and replay
    // (which recorded already, separately).
    AddResult do_add_member(const bytes& kp_bytes,
                             const bytes& leaf_secret) {
        auto kp = tls::get<KeyPackage>(kp_bytes);
        MessageOpts msg_opts{ /*encrypt=*/false, {}, 0 };
        CommitOpts copts;
        // inline_tree=true → the producer packs the ratchet tree
        // into the Welcome itself. The joiner's State-from-Welcome
        // ctor takes a std::optional<TreeKEMPublicKey>; we pass
        // std::nullopt there, so the inline copy is what hydrates
        // the tree. Without this the joiner throws "No tree
        // available".
        copts.inline_tree = true;
        copts.extra_proposals.push_back(state_.add_proposal(kp));
        auto [commit_msg, welcome_msg, new_state] =
            state_.commit(leaf_secret, copts, msg_opts);
        auto commit_bytes  = tls::marshal(commit_msg);
        auto welcome_bytes = tls::marshal(welcome_msg);
        state_ = std::move(new_state);
        AddResult r;
        r.welcome = from_mls_bytes(welcome_bytes);
        r.commit  = from_mls_bytes(commit_bytes);
        return r;
    }

    std::vector<std::uint8_t> do_remove_member(std::uint32_t leaf_index,
                                                 const bytes& leaf_secret) {
        MessageOpts msg_opts{ false, {}, 0 };
        CommitOpts copts;
        copts.extra_proposals.push_back(
            state_.remove_proposal(LeafIndex{ leaf_index }));
        auto [commit_msg, _welcome, new_state] =
            state_.commit(leaf_secret, copts, msg_opts);
        auto commit_bytes = tls::marshal(commit_msg);
        state_ = std::move(new_state);
        return from_mls_bytes(commit_bytes);
    }

    std::vector<std::uint8_t> do_propose_add_member(const bytes& kp_bytes) {
        // Produce the wire-form proposal AND self-handle it so the
        // matching commit_pending later includes it. Without the
        // self-handle our own commit ships empty and the Welcome
        // doesn't carry the new member's KP.
        auto kp = tls::get<KeyPackage>(kp_bytes);
        MessageOpts msg_opts{ false, {}, 0 };
        auto msg = state_.add(kp, msg_opts);
        (void)state_.handle(msg);
        return from_mls_bytes(tls::marshal(msg));
    }

    void do_handle_proposal(const bytes& wire) {
        auto msg = tls::get<MLSMessage>(wire);
        (void)state_.handle(msg);
    }

    AddResult do_commit_pending(const bytes& leaf_secret) {
        MessageOpts msg_opts{ false, {}, 0 };
        CommitOpts copts;
        copts.inline_tree = true;
        auto [commit_msg, welcome_msg, new_state] =
            state_.commit(leaf_secret, copts, msg_opts);
        auto commit_bytes  = tls::marshal(commit_msg);
        auto welcome_bytes = tls::marshal(welcome_msg);
        state_ = std::move(new_state);
        AddResult r;
        r.welcome = from_mls_bytes(welcome_bytes);
        r.commit  = from_mls_bytes(commit_bytes);
        return r;
    }

    void do_apply_commit(const bytes& wire) {
        auto msg = tls::get<MLSMessage>(wire);
        auto next = state_.handle(msg);
        if (!next) {
            throw std::runtime_error(
                "MlsGroup::apply_commit: commit produced no new state "
                "(wrong epoch or unaddressed?)");
        }
        state_ = std::move(*next);
    }

    State                                       state_;
    SignaturePrivateKey                         sig_priv_;
    HPKEPrivateKey                              leaf_priv_;
    std::vector<std::uint8_t>                   seed_blob_;
    std::vector<std::vector<std::uint8_t>>      op_log_;
};

// -----------------------------------------------------------------------------
// Joiner-side wrapper. Holds the generated keys + KeyPackage between
// key_package() publication and complete(welcome). Single-use.
// -----------------------------------------------------------------------------
class PendingMlsJoinImpl final : public PendingMlsJoin {
public:
    PendingMlsJoinImpl(JoinerKeys keys,
                       std::vector<std::uint8_t> identity,
                       bytes group_id_for_seed)
        : keys_(std::move(keys))
        , identity_(std::move(identity))
        , group_id_for_seed_(std::move(group_id_for_seed)) {}

    std::vector<std::uint8_t> key_package() const override {
        return from_mls_bytes(tls::marshal(keys_.key_package));
    }

    std::unique_ptr<MlsGroup> complete(
        std::span<const std::uint8_t> welcome) override;

private:
    JoinerKeys                  keys_;
    std::vector<std::uint8_t>   identity_;
    // The joiner doesn't know the group_id until they parse the
    // Welcome (it's inside). We set it on complete() before building
    // the seed blob.
    bytes                       group_id_for_seed_;
};

// -----------------------------------------------------------------------------
// Seed-blob encoders (one per role).
// -----------------------------------------------------------------------------

std::vector<std::uint8_t> encode_creator_seed(
    const bytes& group_id,
    const bytes& identity,
    const bytes& sig_priv_data,
    const bytes& leaf_priv_data,
    const bytes& init_secret,
    const bytes& leaf_node_marshaled) {
    std::vector<std::uint8_t> out;
    out.reserve(80 + group_id.size() + identity.size() +
                sig_priv_data.size() + leaf_priv_data.size() +
                init_secret.size() + leaf_node_marshaled.size());
    put_u8(out, kSeedVersion);
    put_u8(out, kRoleCreator);
    put_u8(out, static_cast<std::uint8_t>(kSuiteId));
    put_u8(out, 0);
    put_u16(out, static_cast<std::uint16_t>(group_id.size()));
    put_bytes(out, group_id);
    put_u16(out, static_cast<std::uint16_t>(identity.size()));
    put_bytes(out, identity);
    put_u32(out, static_cast<std::uint32_t>(sig_priv_data.size()));
    put_bytes(out, sig_priv_data);
    put_u32(out, static_cast<std::uint32_t>(leaf_priv_data.size()));
    put_bytes(out, leaf_priv_data);
    // Joiner-only fields, all zero-length for creator.
    put_u32(out, 0);
    put_u32(out, 0);
    put_u32(out, 0);
    // Creator-only tail: init_secret + LeafNode bytes.
    put_u32(out, static_cast<std::uint32_t>(init_secret.size()));
    put_bytes(out, init_secret);
    put_u32(out, static_cast<std::uint32_t>(leaf_node_marshaled.size()));
    put_bytes(out, leaf_node_marshaled);
    return out;
}

std::vector<std::uint8_t> encode_joiner_seed(
    const bytes& group_id,
    const bytes& identity,
    const bytes& sig_priv_data,
    const bytes& leaf_priv_data,
    const bytes& init_priv_data,
    const bytes& key_package_marshaled,
    const bytes& welcome_marshaled) {
    std::vector<std::uint8_t> out;
    out.reserve(64 + group_id.size() + identity.size() +
                sig_priv_data.size() + leaf_priv_data.size() +
                init_priv_data.size() +
                key_package_marshaled.size() +
                welcome_marshaled.size());
    put_u8(out, kSeedVersion);
    put_u8(out, kRoleJoiner);
    put_u8(out, static_cast<std::uint8_t>(kSuiteId));
    put_u8(out, 0);
    put_u16(out, static_cast<std::uint16_t>(group_id.size()));
    put_bytes(out, group_id);
    put_u16(out, static_cast<std::uint16_t>(identity.size()));
    put_bytes(out, identity);
    put_u32(out, static_cast<std::uint32_t>(sig_priv_data.size()));
    put_bytes(out, sig_priv_data);
    put_u32(out, static_cast<std::uint32_t>(leaf_priv_data.size()));
    put_bytes(out, leaf_priv_data);
    put_u32(out, static_cast<std::uint32_t>(init_priv_data.size()));
    put_bytes(out, init_priv_data);
    put_u32(out, static_cast<std::uint32_t>(key_package_marshaled.size()));
    put_bytes(out, key_package_marshaled);
    put_u32(out, static_cast<std::uint32_t>(welcome_marshaled.size()));
    put_bytes(out, welcome_marshaled);
    // Creator-only tail — both fields zero-length for joiner.
    put_u32(out, 0);
    put_u32(out, 0);
    return out;
}

// -----------------------------------------------------------------------------
// Decoded-seed value for from_seed_and_commits restoration.
// -----------------------------------------------------------------------------
struct DecodedSeed {
    SeedRole                    role;
    bytes                       group_id;
    bytes                       identity;
    SignaturePrivateKey         sig_priv;
    HPKEPrivateKey              leaf_priv;
    std::optional<HPKEPrivateKey>  init_priv;        // joiner only
    std::optional<KeyPackage>      key_package;      // joiner only
    std::optional<Welcome>         welcome;          // joiner only
    bytes                          creator_init_secret;  // creator only
    std::optional<LeafNode>        creator_leaf_node;    // creator only
};

DecodedSeed decode_seed(std::span<const std::uint8_t> blob) {
    Reader r(blob);
    auto version = r.u8();
    if (version != kSeedVersion) {
        throw std::runtime_error(
            "MlsGroup: seed blob version " + std::to_string(version) +
            " — only v1 is supported");
    }
    auto role_raw = r.u8();
    if (role_raw != kRoleCreator && role_raw != kRoleJoiner) {
        throw std::runtime_error(
            "MlsGroup: seed blob carries unknown role " +
            std::to_string(role_raw));
    }
    auto suite_raw = r.u8();
    if (suite_raw != static_cast<std::uint8_t>(kSuiteId)) {
        // Mismatch is fatal — we'd be feeding keys into the wrong
        // primitives. (When we add suite negotiation later we'll
        // store the suite per-channel and respect it here.)
        throw std::runtime_error(
            "MlsGroup: seed blob cipher suite mismatch (expected "
            "X25519_AES128GCM_SHA256_Ed25519)");
    }
    (void)r.u8();  // reserved

    const auto suite = CipherSuite{ kSuiteId };

    auto gid_len = r.u16();
    auto gid_vec = r.take(gid_len);
    bytes group_id(std::move(gid_vec));

    auto id_len = r.u16();
    auto id_vec = r.take(id_len);
    bytes identity(std::move(id_vec));

    auto sig_len = r.u32();
    auto sig_vec = r.take(sig_len);
    auto sig_priv = SignaturePrivateKey::parse(suite, bytes(std::move(sig_vec)));

    auto leaf_len = r.u32();
    auto leaf_vec = r.take(leaf_len);
    auto leaf_priv = HPKEPrivateKey::parse(suite, bytes(std::move(leaf_vec)));

    auto init_len = r.u32();
    std::optional<HPKEPrivateKey> init_priv;
    if (init_len > 0) {
        auto init_vec = r.take(init_len);
        init_priv =
            HPKEPrivateKey::parse(suite, bytes(std::move(init_vec)));
    }

    auto kp_len = r.u32();
    std::optional<KeyPackage> kp;
    if (kp_len > 0) {
        auto kp_vec = r.take(kp_len);
        kp = tls::get<KeyPackage>(bytes(std::move(kp_vec)));
    }

    auto wel_len = r.u32();
    std::optional<Welcome> wel;
    if (wel_len > 0) {
        auto wel_vec = r.take(wel_len);
        wel = tls::get<Welcome>(bytes(std::move(wel_vec)));
    }

    auto cis_len = r.u32();
    bytes creator_init_secret;
    if (cis_len > 0) {
        auto cis_vec = r.take(cis_len);
        creator_init_secret = bytes(std::move(cis_vec));
    }

    auto ln_len = r.u32();
    std::optional<LeafNode> creator_leaf_node;
    if (ln_len > 0) {
        auto ln_vec = r.take(ln_len);
        creator_leaf_node = tls::get<LeafNode>(bytes(std::move(ln_vec)));
    }

    DecodedSeed out{
        static_cast<SeedRole>(role_raw),
        std::move(group_id),
        std::move(identity),
        std::move(sig_priv),
        std::move(leaf_priv),
        std::move(init_priv),
        std::move(kp),
        std::move(wel),
        std::move(creator_init_secret),
        std::move(creator_leaf_node),
    };
    return out;
}

}  // namespace

// -----------------------------------------------------------------------------
// Out-of-line PendingMlsJoinImpl::complete — has to live below
// MlsGroupImpl so the ctor + encode_joiner_seed are in scope.
// -----------------------------------------------------------------------------
std::unique_ptr<MlsGroup> PendingMlsJoinImpl::complete(
    std::span<const std::uint8_t> welcome_bytes) {
    auto welcome_b = to_mls_bytes(welcome_bytes);
    auto welcome = tls::get<Welcome>(welcome_b);

    // State construction from Welcome — the canonical join path.
    // psks empty (no PSK support today). tree std::nullopt (the
    // sender includes the ratchet tree inline by default, and our
    // commit/welcome producer leaves inline_tree off so mlspp falls
    // back to packing the tree into the Welcome itself).
    State state(keys_.init_priv,
                keys_.leaf_priv,
                keys_.sig_priv,
                keys_.key_package,
                welcome,
                std::nullopt,
                {});

    // We didn't know the group_id at start_join; mls::Welcome carries
    // it. Pull it out of the freshly-built state for the seed.
    auto group_id_b = state.group_id();

    auto seed = encode_joiner_seed(
        group_id_b,
        bytes(std::vector<std::uint8_t>(identity_.begin(), identity_.end())),
        keys_.sig_priv.data,
        keys_.leaf_priv.data,
        keys_.init_priv.data,
        tls::marshal(keys_.key_package),
        welcome_b);

    return std::make_unique<MlsGroupImpl>(
        std::move(state),
        std::move(keys_.sig_priv),
        std::move(keys_.leaf_priv),
        std::move(seed));
}

// -----------------------------------------------------------------------------
// Public factories.
// -----------------------------------------------------------------------------

std::unique_ptr<MlsGroup> MlsGroup::create(
    std::span<const std::uint8_t, 32> creator_identity,
    std::span<const std::uint8_t, 32> group_id) {
    const auto suite = CipherSuite{ kSuiteId };
    auto sig_priv  = SignaturePrivateKey::generate(suite);
    auto leaf_priv = HPKEPrivateKey::generate(suite);
    auto cred      = Credential::basic(to_mls_bytes(creator_identity));
    auto leaf_node = LeafNode(suite,
                              leaf_priv.public_key,
                              sig_priv.public_key,
                              cred,
                              Capabilities::create_default(),
                              Lifetime::create_default(),
                              {},
                              sig_priv);

    auto group_id_b = to_mls_bytes(group_id);
    auto identity_b = to_mls_bytes(creator_identity);

    // Generate the epoch-0 init_secret in user space so we can save
    // it alongside the seed and reach the SAME KeyScheduleEpoch on
    // restore. The default empty-group ctor would generate
    // random_bytes internally and discard it; the FinBit mlspp patch
    // adds an override ctor that takes init_secret as a parameter.
    // (mls::random_bytes is the same RNG mlspp uses internally.)
    auto init_secret = random_bytes(suite.secret_size());

    State state(group_id_b, suite, leaf_priv, sig_priv,
                leaf_node, ExtensionList{}, init_secret);

    // LeafNode embeds Lifetime (current time at construction) and
    // Capabilities, both of which feed into the tree hash that
    // contributes to KeyScheduleEpoch's group context. We must
    // restore the EXACT same LeafNode bytes on reload, so persist
    // them rather than reconstructing from defaults.
    auto leaf_node_marshaled = tls::marshal(leaf_node);

    auto seed = encode_creator_seed(
        group_id_b,
        identity_b,
        sig_priv.data,
        leaf_priv.data,
        init_secret,
        leaf_node_marshaled);

    return std::make_unique<MlsGroupImpl>(
        std::move(state),
        std::move(sig_priv),
        std::move(leaf_priv),
        std::move(seed));
}

std::unique_ptr<MlsGroup> MlsGroup::from_blob(std::span<const std::uint8_t> blob) {
    // Bundled "MGB1" container = magic + seed + op list. Split apart
    // and delegate to from_seed_and_log.
    if (blob.size() < 8 || blob[0] != 'M' || blob[1] != 'G' ||
        blob[2] != 'B' || blob[3] != '1') {
        throw std::runtime_error(
            "MlsGroup::from_blob: missing 'MGB1' magic — pass either a "
            "bundled blob from serialize() or use from_seed_and_log "
            "for the split form");
    }
    Reader r(blob.subspan(4));
    auto seed_len = r.u32();
    auto seed_bytes = r.take(seed_len);
    auto op_count = r.u32();
    std::vector<std::vector<std::uint8_t>> ops;
    ops.reserve(op_count);
    for (std::uint32_t i = 0; i < op_count; ++i) {
        auto op_len = r.u32();
        ops.push_back(r.take(op_len));
    }
    return MlsGroup::from_seed_and_log(
        std::span<const std::uint8_t>(seed_bytes.data(), seed_bytes.size()),
        ops);
}

std::unique_ptr<MlsGroup> MlsGroup::from_seed_and_log(
    std::span<const std::uint8_t> seed,
    const std::vector<std::vector<std::uint8_t>>& ops) {
    auto decoded = decode_seed(seed);

    const auto suite = CipherSuite{ kSuiteId };

    // Build the initial State per role.
    std::optional<State> initial;
    if (decoded.role == kRoleCreator) {
        if (decoded.creator_init_secret.empty() ||
            !decoded.creator_leaf_node) {
            throw std::runtime_error(
                "MlsGroup: creator seed missing init_secret or "
                "leaf_node — was it produced by a pre-persistence-"
                "patch build?");
        }
        // Use the persisted LeafNode bytes verbatim. Reconstructing
        // it from defaults here would yield different Lifetime /
        // Capabilities and a different tree hash.
        // FinBit-patched ctor that takes init_secret explicitly so
        // we land on the same KeyScheduleEpoch as the original
        // create() call.
        initial.emplace(decoded.group_id,
                        suite,
                        decoded.leaf_priv,
                        decoded.sig_priv,
                        *decoded.creator_leaf_node,
                        ExtensionList{},
                        decoded.creator_init_secret);
    } else {
        if (!decoded.init_priv || !decoded.key_package || !decoded.welcome) {
            throw std::runtime_error(
                "MlsGroup: joiner seed missing init_priv / key_package "
                "/ welcome");
        }
        initial.emplace(*decoded.init_priv,
                        decoded.leaf_priv,
                        decoded.sig_priv,
                        *decoded.key_package,
                        *decoded.welcome,
                        std::nullopt,
                        std::map<bytes, bytes>{});
    }

    State state = std::move(*initial);

    // Build the wrapper at epoch 0, THEN replay each op through the
    // wrapper's replay_op so the same do_*** code paths run as
    // during the live mutators. replay_op also re-appends the op
    // bytes to op_log_, leaving the restored group in a state that
    // can be re-serialized identically.
    auto group = std::make_unique<MlsGroupImpl>(
        std::move(state),
        std::move(decoded.sig_priv),
        std::move(decoded.leaf_priv),
        std::vector<std::uint8_t>(seed.begin(), seed.end()),
        std::vector<std::vector<std::uint8_t>>{});

    for (std::size_t i = 0; i < ops.size(); ++i) {
        try {
            group->replay_op(std::span<const std::uint8_t>(
                ops[i].data(), ops[i].size()));
        } catch (const std::exception& e) {
            throw std::runtime_error(
                "MlsGroup::from_seed_and_log: replay of op " +
                std::to_string(i) + " failed: " + e.what());
        }
    }
    return group;
}

std::unique_ptr<PendingMlsJoin> MlsGroup::start_join(
    std::span<const std::uint8_t, 32> joiner_identity) {
    const auto suite = CipherSuite{ kSuiteId };
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred     = Credential::basic(to_mls_bytes(joiner_identity));
    auto keys = build_joiner_keys(suite, std::move(sig_priv), std::move(cred));

    std::vector<std::uint8_t> identity(joiner_identity.begin(),
                                        joiner_identity.end());
    return std::make_unique<PendingMlsJoinImpl>(std::move(keys),
                                                 std::move(identity),
                                                 bytes{});
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

std::unique_ptr<MlsGroup> MlsGroup::from_seed_and_log(
    std::span<const std::uint8_t>,
    const std::vector<std::vector<std::uint8_t>>&) {
    unimpl("from_seed_and_log");
}

std::unique_ptr<PendingMlsJoin> MlsGroup::start_join(
    std::span<const std::uint8_t, 32>) {
    unimpl("start_join");
}

}  // namespace fb::crypto

#endif  // FB_HAVE_MLS
