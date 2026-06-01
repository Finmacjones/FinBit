// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// fb::handshake — the canonical home for FinBit's session-bootstrap primitives.
//
// Lifted out of tools/fb-cli/main.cpp and client-desktop/src/chat_client.cpp,
// which previously duplicated the same ~120-line block: the X25519Pair, its
// derivation from an Ed25519 identity, the X3DH ECDH (`derive_shared_secret`),
// and the Tier-7 PQ-hybrid extension (`derive_hybrid_send_from_bundle`,
// `derive_hybrid_recv_from_env`).
//
// The wire format owned by these helpers:
//   * Classical X25519 ECDH → HKDF-SHA256(info = "FinBit-X3DH-v0") → 32-byte
//     shared secret.
//   * Tier-7 PQ extension: when the peer published a PreKeyBundle.pq_pubkey
//     or DhtPrekeyRecord.pq_pubkey (1184B ML-KEM-768), the sender encaps,
//     ships the 1088B Envelope.pq_ct, and HKDF-combines both halves via
//     fb::crypto::hybrid::combine_x25519_mlkem768 — a single hybrid root
//     that's secure as long as EITHER half is secure (PQXDH-style).
//   * Identity-bound PQ keypair: the PQ secret is NOT persisted — it's
//     re-derived from the existing Ed25519 identity seed via HKDF +
//     OpenSSL's ML-KEM-768 seeded keygen. Same user → same long-term PQ
//     keypair across runs, zero extra at-rest state.
//
// Backward compat: every helper falls back to pure X25519 when the peer's
// pq_pubkey is empty OR the inbound envelope's pq_ct is empty. New clients
// interoperate with pre-PQ peers without losing functionality (they just
// don't get harvest-now defense for THAT envelope).
// =============================================================================

#include "fb/crypto/identity.hpp"
#include "fb/crypto/pq_kem.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

// Forward-declare the proto types so the header doesn't require every
// consumer to include the generated protobuf headers. The .cpp pulls them.
namespace fb::proto {
class PreKeyBundle;
class Envelope;
}  // namespace fb::proto

namespace fb::handshake {

// Curve25519 keypair derived from an Ed25519 identity. The mapping is
// deterministic (crypto_sign_ed25519_*_to_curve25519); both halves are
// recomputable from the Identity object, so this struct is transient
// in-memory state, not persisted.
struct X25519Pair {
    std::array<std::uint8_t, 32> pub{};
    std::array<std::uint8_t, 32> priv{};
};

// Convert an Ed25519 identity's secret + public to the matching Curve25519
// keypair for ECDH. Throws std::runtime_error if libsodium's conversion
// fails (only on malformed identity material — should be impossible for
// any Identity built via from_seed or generate).
[[nodiscard]] X25519Pair derive_x25519(const fb::crypto::Identity& id);

// X3DH-style ECDH + HKDF-SHA256. Computes crypto_scalarmult(mine.priv,
// peer_pub) then HKDF-Extract(empty) + HKDF-Expand(info = "FinBit-X3DH-v0")
// to 32 bytes. The output feeds the Double Ratchet root directly.
//
// Throws std::runtime_error on a low-order peer pubkey (scalarmult
// returns non-zero, indicating a key in the small-subgroup attack space).
[[nodiscard]] std::array<std::uint8_t, 32> derive_shared_secret(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_pub);

// ---------------------------------------------------------------------------
// Tier-7 PQ-hybrid wire-up.
// ---------------------------------------------------------------------------

// Deterministic ML-KEM-768 keypair + a binding Ed25519 signature.
//
// The keypair is reproducible from the Ed25519 identity seed via
// fb::crypto::derive_pq_seed_from_identity_seed → 64 bytes → OpenSSL's
// ML-KEM-768 seeded keygen. The signature is `identity.sign(pub)` and
// gets shipped alongside the pubkey in PreKeyBundle / PrekeyRecord so
// peers can verify the PQ key is bound to the same long-term identity
// (defeats a MITM that strips PQ and substitutes a key it controls).
// The 2400-byte ML-KEM secret is long-term identity material (re-derivable
// from the Ed25519 seed). Mirror fb::crypto::Identity's hygiene: wipe `sec`
// on destruction and on move-from so it never lingers in freed heap (audit
// PQ HIGH-1). Copies are kept (defaulted) for the rare value-copy; the live
// copy is wiped by its own destructor.
struct PqIdentity {
    fb::crypto::pq::MlKem768Pub  pub{};
    fb::crypto::pq::MlKem768Sec  sec{};
    fb::crypto::Sig              pubkey_sig{};

    PqIdentity() = default;
    ~PqIdentity() { sodium_memzero(sec.data(), sec.size()); }
    PqIdentity(const PqIdentity&) = default;
    PqIdentity& operator=(const PqIdentity&) = default;
    PqIdentity(PqIdentity&& o) noexcept { *this = std::move(o); }
    PqIdentity& operator=(PqIdentity&& o) noexcept {
        if (this != &o) {
            pub = o.pub;
            sec = o.sec;
            pubkey_sig = o.pubkey_sig;
            sodium_memzero(o.sec.data(), o.sec.size());
        }
        return *this;
    }
};

[[nodiscard]] PqIdentity derive_pq_identity(
    const fb::crypto::Identity& id,
    std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes> seed);

// Sender-side hybrid: ECDH + ML-KEM-768 encap + HKDF-combine.
//
// `peer_pq_pub` may be:
//   * Empty (1184-byte legacy peer / not advertised) → falls back to
//     `derive_shared_secret` and returns empty `pq_ct`.
//   * Exactly 1184 bytes → encap against the peer's PQ pubkey, combine.
//   * Any other size → throws std::runtime_error.
struct HybridSendResult {
    std::array<std::uint8_t, 32>  shared{};
    std::vector<std::uint8_t>     pq_ct;
};

[[nodiscard]] HybridSendResult derive_hybrid_send(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    std::span<const std::uint8_t> peer_pq_pub);

// Receiver-side hybrid: ECDH + ML-KEM-768 decap + HKDF-combine.
// Symmetric to derive_hybrid_send. Empty `pq_ct` → pure-X25519 fallback.
[[nodiscard]] std::array<std::uint8_t, 32> derive_hybrid_recv(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SecBytes> my_pq_sec,
    std::span<const std::uint8_t> pq_ct);

// Bundle-aware wrapper: extracts pq_pubkey from a PreKeyBundle, verifies
// the binding sig (rejects MITM substitution rather than silently
// downgrading), then calls derive_hybrid_send. Empty pq_pubkey on the
// bundle is the legitimate "no PQ advertised" case.
[[nodiscard]] HybridSendResult derive_hybrid_send_from_bundle(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    const fb::proto::PreKeyBundle& bundle);

// Envelope-aware wrapper: reads pq_ct from an Envelope and calls
// derive_hybrid_recv. Empty pq_ct on the envelope → pre-PQ sender path.
[[nodiscard]] std::array<std::uint8_t, 32> derive_hybrid_recv_from_env(
    const X25519Pair& mine,
    std::span<const std::uint8_t, 32> peer_x,
    std::span<const std::uint8_t, fb::crypto::pq::kMlKem768SecBytes> my_pq_sec,
    const fb::proto::Envelope& env);

// ---------------------------------------------------------------------------
// Sealed sender (Signal-style metadata defense).
//
// When a session is established (the peer has decrypted at least one of our
// envelopes), subsequent envelopes ship with Envelope.sender_pubkey EMPTY —
// the relay no longer learns who is talking to whom. The sender identity
// rides inside the AEAD-encrypted DmPayload as `sealed_sender_pubkey` +
// `sealed_sender_sig`, where the sig is Ed25519 over the same outer AAD
// (envelope_id || timestamp_ms_be) the AEAD already authenticates. The
// recipient verifies the sig under the claimed pubkey AND requires the
// claimed pubkey to match the session it decrypted under (defeats relay
// reordering envelopes between sessions).
//
// First-contact envelopes (no session yet on either side) keep the legacy
// plaintext sender_pubkey on the wire — one-time identity reveal is
// unavoidable without an ephemeral-sender handshake (Noise_NK etc.). All
// later envelopes from the same sender are sealed.
// ---------------------------------------------------------------------------

// Build the bytes that the sealed-sender sig covers. Equal to
//   "FinBit-SealedSender-v1" || envelope_id || u64_be(timestamp_ms)
//        || recipient_pubkey
// The leading domain tag (audit M2) keeps a sealed-sender Ed25519 sig from
// being confused with any other identity-key signature in the protocol. The
// envelope_id || timestamp portion is the same outer AAD the AEAD
// authenticates (so an envelope can't be replayed under a different id or a
// shifted timestamp), and the trailing recipient_pubkey binds the seal to
// its intended recipient (so a relay can't lift the claim onto an envelope
// routed elsewhere). `recipient_pubkey` is the recipient's Ed25519 identity
// pubkey: the destination peer's on the sender side, one's own on the
// verify side.
[[nodiscard]] std::vector<std::uint8_t> sealed_sender_sig_input(
    std::span<const std::uint8_t> envelope_id,
    std::uint64_t timestamp_ms,
    std::span<const std::uint8_t> recipient_pubkey);

struct SealedSenderFields {
    fb::crypto::PubKey pubkey{};
    fb::crypto::Sig    sig{};
};

// Sender side: produce { pubkey, sig } to attach as
// DmPayload.sealed_sender_pubkey + sealed_sender_sig. `recipient_pubkey` is
// the destination peer's Ed25519 identity pubkey (bound into the sig).
[[nodiscard]] SealedSenderFields make_sealed_sender_fields(
    const fb::crypto::Identity& id,
    std::span<const std::uint8_t> envelope_id,
    std::uint64_t timestamp_ms,
    std::span<const std::uint8_t> recipient_pubkey);

// Recipient side: verify that the embedded sender claim is genuine. Pass
// one's OWN identity pubkey as `recipient_pubkey` (it must match what the
// sender bound). The caller is expected to ALSO check claimed_pubkey ==
// session.peer_pub (this function doesn't have access to session state —
// keep it pure).
[[nodiscard]] bool verify_sealed_sender(
    std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes> claimed_pubkey,
    std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>    claimed_sig,
    std::span<const std::uint8_t> envelope_id,
    std::uint64_t timestamp_ms,
    std::span<const std::uint8_t> recipient_pubkey) noexcept;

// ---------------------------------------------------------------------------
// Hybrid signatures — Ed25519 + ML-DSA-65.
//
// Mirrors the PQ-KEM hybrid story (Tier 7) for the signing side. Every
// hybrid-signed message carries BOTH an Ed25519 sig (fast, small, what the
// rest of the world trusts) AND an ML-DSA-65 sig (slow, 3.3 KB, PQ-secure).
// A verifier requires BOTH to pass — so an attacker with a future CRQC who
// breaks Ed25519 (Shor's) still has to forge ML-DSA-65 (a PQ-hard lattice
// problem) to spoof an identity attestation. Security = max(strengths).
//
// Where to use: long-term identity bindings (prekey-bundle signed_prekey
// signature, pq_pubkey binding sig, identity-claim signatures, hello-ack).
// Where NOT to use: per-envelope sigs like sealed_sender_sig (3.3 KB per
// envelope is too heavy; the AEAD + ratchet provide adequate per-message
// auth and the sealed sender's anti-replay binding is to the AEAD-
// authenticated AAD).
//
// HONEST LIMITATION: the PQ pubkey itself (PqSigIdentity::pub) must be
// distributed with a binding signature back to the Ed25519 identity — and
// that binding sig is Ed25519-only today. A CRQC attacker can forge the
// binding, swap in their own PqSigIdentity, then sign anything with it.
// Full PQ-rooted identity is a documented next-tier upgrade (move identity
// from Ed25519 to Ed25519+ML-DSA at the protocol root); this commit ships
// the building blocks for that, plus partial defense against non-CRQC
// future weaknesses in Ed25519.
// ---------------------------------------------------------------------------

// As PqIdentity: the 4032-byte ML-DSA secret is long-term identity material;
// wipe it on destruction and on move-from (audit PQ HIGH-1).
struct PqSigIdentity {
    fb::crypto::pq::MlDsa65Pub  pub{};
    fb::crypto::pq::MlDsa65Sec  sec{};
    fb::crypto::Sig             pubkey_sig{};   // Ed25519 binding to identity

    PqSigIdentity() = default;
    ~PqSigIdentity() { sodium_memzero(sec.data(), sec.size()); }
    PqSigIdentity(const PqSigIdentity&) = default;
    PqSigIdentity& operator=(const PqSigIdentity&) = default;
    PqSigIdentity(PqSigIdentity&& o) noexcept { *this = std::move(o); }
    PqSigIdentity& operator=(PqSigIdentity&& o) noexcept {
        if (this != &o) {
            pub = o.pub;
            sec = o.sec;
            pubkey_sig = o.pubkey_sig;
            sodium_memzero(o.sec.data(), o.sec.size());
        }
        return *this;
    }
};

// Derive the deterministic ML-DSA-65 keypair from the Ed25519 identity seed
// via derive_pq_sig_seed_from_identity_seed. Mirrors derive_pq_identity
// (which does the ML-KEM-768 equivalent). Both PQ-sig and PQ-KEM keypairs
// can therefore be regenerated from the same 32-byte Ed25519 seed — no
// extra at-rest secrets to persist.
[[nodiscard]] PqSigIdentity derive_pq_sig_identity(
    const fb::crypto::Identity& id,
    std::span<const std::uint8_t, fb::crypto::kIdentitySeedBytes> seed);

struct HybridSignature {
    fb::crypto::Sig             ed25519{};
    fb::crypto::pq::MlDsa65Sig  pq{};
};

// Sign `message` with both halves. Output is two parallel sigs the verifier
// checks independently.
[[nodiscard]] HybridSignature hybrid_sign(
    const fb::crypto::Identity& classical,
    const PqSigIdentity&        pq,
    std::span<const std::uint8_t> message);

// Verify a hybrid signature. Returns true iff BOTH sigs verify under their
// respective pubkeys. Always evaluates both checks (non-short-circuit `&`)
// so a passing half can't mask a failing one — but this is NOT constant-
// time and intentionally so: the inputs are PUBLIC signature material, so a
// timing leak of which half is invalid has no value to an attacker.
[[nodiscard]] bool hybrid_verify(
    std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>     ed25519_pub,
    std::span<const std::uint8_t, fb::crypto::pq::kMlDsa65PubBytes>     pq_pub,
    std::span<const std::uint8_t> message,
    const HybridSignature& sig) noexcept;

// Populate the four PQ-sig fields on a PreKeyBundle. The caller must have
// already set identity_pubkey, signed_prekey, signed_prekey_sig, pq_pubkey,
// pq_pubkey_sig. This adds:
//   * pq_sig_pubkey         — the ML-DSA-65 pubkey
//   * pq_sig_pubkey_sig     — Ed25519 sig over pq_sig_pubkey by the identity
//   * signed_prekey_sig_pq  — ML-DSA-65 sig over signed_prekey by pq_sig_pubkey
//   * pq_pubkey_sig_pq      — ML-DSA-65 sig over pq_pubkey by pq_sig_pubkey
void add_pq_sig_fields_to_bundle(
    fb::proto::PreKeyBundle& bundle,
    const fb::crypto::Identity& classical,
    const PqSigIdentity& pq);

// Verify the PQ-sig fields on a peer's PreKeyBundle.
//
// Returns true iff EITHER (a) the bundle is pre-PQ-sig (all four PQ-sig
// fields empty) — Ed25519-only fallback path — OR (b) all four fields are
// present, the ML-KEM-768 pq_pubkey is ALSO present and its ML-DSA binding
// sig (pq_pubkey_sig_pq) verifies, and every hybrid signature verifies.
// Returns false on any partial/mismatched state (which would only happen
// with a MITM that stripped some fields but not others — refuse rather than
// silently downgrade).
//
// KEM-strip defense (audit PQ CRITICAL-1): a bundle that advertises a PQ-sig
// identity MUST carry its KEM pubkey. Nothing else commits to the KEM key's
// presence, so without this a relay could strip pq_pubkey + its sigs and
// force a silent downgrade to classical-only X25519 (defeating harvest-now-
// decrypt-later). A genuine PQ publisher always co-publishes both, so the
// presence requirement costs nothing and closes the strip.
//
// The verifier does NOT also check the existing Ed25519 signed_prekey_sig
// or pq_pubkey_sig — those are checked elsewhere (the call sites that
// already exist in derive_hybrid_send_from_bundle). This helper only
// adds the PQ half.
[[nodiscard]] bool verify_bundle_pq_sigs(const fb::proto::PreKeyBundle& bundle) noexcept;

// TOFU PQ-capability downgrade policy — closes the full-field-strip residual
// that verify_bundle_pq_sigs structurally cannot catch.
//
// verify_bundle_pq_sigs rejects a *partial* strip (some PQ fields gone, some
// kept — provably a MITM). But a MITM that strips EVERY PQ field hands the
// victim a bundle byte-indistinguishable from a genuine pre-PQ (legacy) peer:
// nothing inside a single bundle commits to "this identity is PQ-capable", so
// at the bundle layer the strip is invisible. Only cross-session memory closes
// it. Once we have seen a peer advertise an ML-KEM pubkey we pin that fact; a
// later bundle/record from the same identity that drops PQ is a downgrade
// attempt and must be refused — trust-on-first-use, the same model SSH uses
// for host keys.
//
// `previously_pq_capable` is the persisted per-peer pin; `now_advertises_pq`
// is whether the freshly fetched bundle/record carries an ML-KEM pubkey
// (i.e. `!pq_pubkey().empty()`). Pure function: the single source of the rule,
// unit-tested in isolation. Returns true ⇒ caller MUST refuse the bundle.
[[nodiscard]] constexpr bool is_pq_capability_downgrade(
        bool previously_pq_capable, bool now_advertises_pq) noexcept {
    return previously_pq_capable && !now_advertises_pq;
}

}  // namespace fb::handshake
