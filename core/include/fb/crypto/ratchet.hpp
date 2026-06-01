// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Signal Double Ratchet — Phase 0 implementation.
//
// Reference: https://signal.org/docs/specifications/doubleratchet/
//
// Implemented:
//   - DH ratchet on every received message with a new peer DH public key
//   - Symmetric chain ratchet via HMAC-SHA256(ck, 0x01)/HMAC-SHA256(ck, 0x02)
//   - HKDF-SHA256 root-key step
//   - AES-256-GCM AEAD with fresh per-message keys (zero nonce is safe because
//     each key is used at most once)
//   - Skipped message keys cached up to MAX_SKIP per chain; out-of-order and
//     reordered delivery work
//   - Replay rejection (a key is consumed on first successful decrypt)
//
// NOT implemented in Phase 0 (deferred):
//   - Header encryption (HE) variant
//   - Cross-chain skipped-key migration (only the most recent receive chain's
//     skipped keys are retained — sufficient for normal Signal-style sessions)
//   - X3DH initial key agreement (caller supplies a 32-byte shared secret)
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace fb::crypto {

class DoubleRatchet {
public:
    static constexpr std::size_t kMaxSkip = 1000;

    // Initialize the initiator's side of a fresh session.
    //   shared_secret : 32 bytes from the prior key agreement (Noise / X3DH).
    //   peer_dh_pub   : the responder's signed-prekey public X25519 key.
    [[nodiscard]] static DoubleRatchet init_alice(std::span<const std::uint8_t, 32> shared_secret,
                                                  std::span<const std::uint8_t, 32> peer_dh_pub);

    // Initialize the responder's side. The responder uses its signed-prekey
    // X25519 keypair as the initial DHs.
    [[nodiscard]] static DoubleRatchet init_bob(
        std::span<const std::uint8_t, 32> shared_secret,
        std::span<const std::uint8_t, 32> our_dh_keypair_priv,
        std::span<const std::uint8_t, 32> our_dh_keypair_pub);

    DoubleRatchet(const DoubleRatchet&)            = delete;
    DoubleRatchet& operator=(const DoubleRatchet&) = delete;
    DoubleRatchet(DoubleRatchet&&) noexcept;
    DoubleRatchet& operator=(DoubleRatchet&&) noexcept;
    ~DoubleRatchet();

    // Serialize-and-encrypt a plaintext message. Returns serialized
    // RatchetMessage protobuf bytes.
    [[nodiscard]] std::vector<std::uint8_t> encrypt(std::span<const std::uint8_t> plaintext,
                                                    std::span<const std::uint8_t> aad);

    // Decrypt a serialized RatchetMessage. Returns plaintext on success;
    // std::nullopt on tag mismatch / replay / older-than-MAX_SKIP / malformed
    // header.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt(
        std::span<const std::uint8_t> ratchet_msg, std::span<const std::uint8_t> aad);

    // Snapshot-then-decrypt: attempt decrypt under a state snapshot; on any
    // failure (parse / AEAD MAC / out-of-window) restore the prior state
    // so the ratchet can be re-tried against another envelope. Used by
    // the sealed-sender recipient path, where the relay-visible envelope
    // omits sender_pubkey and the recipient must try each candidate
    // session until one decrypts. The default `decrypt()` ABOVE mutates
    // state BEFORE the MAC check (per the Signal DR spec, advancing the
    // chain to derive the message key) — calling it against the wrong
    // session would corrupt that session permanently. This variant pays
    // the cost of one State copy per attempt to stay safe.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> try_decrypt(
        std::span<const std::uint8_t> ratchet_msg, std::span<const std::uint8_t> aad);

    // Cheap O(1), NON-MUTATING pre-filter for the sealed-sender try-all
    // path (audit finding H1). Parses the RatchetMessage header only and
    // returns true iff this message plausibly belongs to THIS session's
    // current receive chain — i.e. header_dh_pub == our current peer DH
    // AND the implied skip distance (pn/n) is within kMaxSkip. Lets the
    // recipient skip the expensive try_decrypt (which derives up to
    // kMaxSkip message keys BEFORE the MAC check) for sessions that
    // obviously don't match, turning O(N · kMaxSkip) into O(N) header
    // parses + O(1) full attempts. A `false` here never causes a missed
    // message: a genuinely-matching message always has header_dh ==
    // dhr_pub for the in-order/small-skip case; the rare
    // just-DH-ratcheted case falls back to the full try-all (still
    // bounded by the same kMaxSkip cap this method enforces).
    //
    // Returns false on a malformed header or an out-of-window skip
    // distance — the latter is the DoS guard: an attacker-crafted
    // header with pn=n=2^32-1 is rejected here without deriving a
    // single key.
    [[nodiscard]] bool header_matches_recv_chain(
        std::span<const std::uint8_t> ratchet_msg) const noexcept;

    // PIMPL — full definition lives in ratchet.cpp. Public so internal
    // helpers in the .cpp can take `State&` without friend declarations;
    // the type is forward-only here so consumers see no internals.
    struct State;

private:
    DoubleRatchet();
    std::unique_ptr<State> state_;
};

}  // namespace fb::crypto
