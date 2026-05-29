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

#include <array>
#include <cstdint>
#include <span>
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
struct PqIdentity {
    fb::crypto::pq::MlKem768Pub  pub{};
    fb::crypto::pq::MlKem768Sec  sec{};
    fb::crypto::Sig              pubkey_sig{};
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
// envelope_id || u64_be(timestamp_ms) — the same outer AAD the AEAD
// authenticates. Producing both signatures over the same bytes means an
// envelope can't be replayed under a different id or with a shifted
// timestamp without invalidating both checks at once.
[[nodiscard]] std::vector<std::uint8_t> sealed_sender_sig_input(
    std::span<const std::uint8_t> envelope_id,
    std::uint64_t timestamp_ms);

struct SealedSenderFields {
    fb::crypto::PubKey pubkey{};
    fb::crypto::Sig    sig{};
};

// Sender side: produce { pubkey, sig } to attach as
// DmPayload.sealed_sender_pubkey + sealed_sender_sig.
[[nodiscard]] SealedSenderFields make_sealed_sender_fields(
    const fb::crypto::Identity& id,
    std::span<const std::uint8_t> envelope_id,
    std::uint64_t timestamp_ms);

// Recipient side: verify that the embedded sender claim is genuine. The
// caller is expected to ALSO check claimed_pubkey == session.peer_pub
// (this function doesn't have access to session state — keep it pure).
[[nodiscard]] bool verify_sealed_sender(
    std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes> claimed_pubkey,
    std::span<const std::uint8_t, fb::crypto::kIdentitySigBytes>    claimed_sig,
    std::span<const std::uint8_t> envelope_id,
    std::uint64_t timestamp_ms) noexcept;

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

struct PqSigIdentity {
    fb::crypto::pq::MlDsa65Pub  pub{};
    fb::crypto::pq::MlDsa65Sec  sec{};
    fb::crypto::Sig             pubkey_sig{};   // Ed25519 binding to identity
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
// respective pubkeys. Constant-time-ish: always evaluates both checks even
// when the first fails (defeats timing-side-channel inference about which
// half is wrong).
[[nodiscard]] bool hybrid_verify(
    std::span<const std::uint8_t, fb::crypto::kIdentityPubKeyBytes>     ed25519_pub,
    std::span<const std::uint8_t, fb::crypto::pq::kMlDsa65PubBytes>     pq_pub,
    std::span<const std::uint8_t> message,
    const HybridSignature& sig) noexcept;

}  // namespace fb::handshake
