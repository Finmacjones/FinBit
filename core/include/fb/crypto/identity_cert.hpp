// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// =============================================================================
// Identity-pinned TLS certificates.
//
// In FinBit's serverless model the user's identity IS their Ed25519 keypair.
// For peer-to-peer TLS connections we want the TLS layer to attest to that
// same identity rather than hauling in a separate PKI. The pattern:
//
//   * Each peer derives a self-signed X.509 v3 cert from their Ed25519
//     identity key. The cert's SubjectPublicKeyInfo is THE Ed25519 public
//     key — there is no separate "TLS key" to manage. OpenSSL signs with
//     the same key (Ed25519 pure-EdDSA).
//   * Peers exchange certs during the TLS handshake (mutual auth on
//     PeerNet; client-cert presentation on outbound dials).
//   * After the handshake, each side calls extract_pubkey_from_cert to
//     pull the peer's pubkey out of their cert. The application-layer
//     code (DhtNode, UsernameLog, ChatClient) compares this against the
//     pubkey it expected — if they don't match, the connection is
//     rejected.
//
// This closes the v0 PeerNet trust gap: previously a connecting peer
// could lie about their `sender_pubkey` in PeerEnvelope. Now the TLS
// layer cryptographically attests to the peer's identity before any
// application bytes flow.
//
// Why self-signed instead of a chain back to a CA: the identity key IS
// the trust root. There's no authority above it that we'd want to defer
// to. Anyone validating the cert against a system trust store would
// REJECT it — and that's fine, because we're not trying to chain. The
// PeerNet TLS path uses SSL_VERIFY_NONE for the chain check (no useful
// CA exists) and instead does the pinned-pubkey check at the
// application layer above OpenSSL.
//
// Build-time switch: only available when FB_HAVE_OPENSSL=1. Without
// OpenSSL the helpers throw — direct-P2P is gated on TLS anyway, so
// mutual-auth is gated on the same dependency.
// =============================================================================

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace fb::crypto {

struct PemCertKey {
    std::string cert_pem;   // PEM-encoded X.509 v3 cert
    std::string key_pem;    // PEM-encoded Ed25519 private key
};

// Generate a self-signed cert wrapping the given Ed25519 identity. The
// 32-byte input is the Ed25519 SEED (matches Identity::secret_key()
// minus the appended pubkey half). Returns the cert + key as PEM
// strings — caller writes them to temp files (or feeds them to a BIO)
// to hand to OpenSSL.
//
// validity_days defaults to 365. The cert is regenerated on each call,
// so re-running with the same seed but different validity_days produces
// a different cert (different notBefore/notAfter timestamps).
[[nodiscard]] PemCertKey generate_identity_cert(
    std::span<const std::uint8_t, 32> identity_seed,
    int validity_days = 365);

// Pull the Ed25519 public key out of a PEM-encoded X.509 cert. Returns
// nullopt if the cert isn't parseable, doesn't carry an Ed25519 key,
// or the key isn't 32 bytes. Used after a TLS handshake to compare the
// peer's presented identity against the expected pubkey.
[[nodiscard]] std::optional<std::array<std::uint8_t, 32>>
    extract_pubkey_from_cert_pem(const std::string& cert_pem);

}  // namespace fb::crypto
