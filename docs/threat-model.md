# FinBit threat model

This document is gate-required before Phase 0 ships per the architecture plan.
It states what FinBit defends against, what it does NOT, and where the
trust boundaries sit.

## What FinBit defends against

1. **A fully-honest-but-curious central server** that records and stores all
   ciphertext indefinitely. The server cannot recover plaintext from any
   message body it has ever relayed. Verified end-to-end by the
   `tools/e2e/dm_roundtrip.sh` test which (a) uses a random plaintext
   marker per run and (b) asserts that marker never appears in the server
   log.

2. **A passive on-path network attacker** (state actor MitM, ISP, hotel
   wifi). All transport is wrapped in TLS in production deployments
   (terminate at the relay), and the message body is independently
   AES-256-GCM-encrypted via the Double Ratchet so even compromised TLS
   does not reveal plaintext.

3. **An active on-path attacker tampering with ciphertext.** AEAD tags
   reject any modification, including header fields covered by the AAD
   (`envelope_id || timestamp_ms` at the envelope layer; `header_dh_pub
   || pn || n` at the ratchet layer). Verified by the
   `Aes256GcmKat.TamperedTag/Aad` and `Ratchet.TamperedAad/Ciphertext`
   unit tests.

4. **Replay of a successfully delivered message.** Message keys are
   consumed on first successful decrypt; subsequent presentation of the
   same ciphertext is rejected. Verified by `Ratchet.ReplayIsRejected`.

5. **Bandwidth flooding via a misbehaving sender.** The server applies a
   per-pubkey token bucket (50 KB/s sustained, 500 KB burst by default)
   to inbound envelopes; over-quota traffic is dropped with a
   `RATE_EXCEEDED` ControlMessage. Same enforcement extends to peer relays
   in Phase 5 with both endpoints of a relayed flow accounted to bound
   weaponized-receiver DDoS.

6. **Future server compromise** (key extraction post-fact). Forward
   secrecy via the Double Ratchet means messages exchanged before the
   compromise stay sealed even if every key the server ever held leaks.
   Phase 1 extends this property to channels via MLS (RFC 9420).

## What FinBit does NOT defend against (yet — by phase)

| Threat                                       | Mitigation phase | Notes |
|----------------------------------------------|------------------|-------|
| Server-side metadata harvesting (who-talks-to-whom timing) | Phase 5 (P2P fan-out reduces server visibility); arguably **never** fully — true metadata privacy requires Tor/mixnet routing. | Document this prominently in the user-facing privacy notice. |
| Channel/server membership confidentiality    | Phase 1 (MLS) — server learns only that some opaque group exists, not who's in it. | mlspp's "anonymous credentials" mode. |
| Voice/video confidentiality through an SFU   | Phase 2 (SFrame on libwebrtc encoded-frame transforms) | SFU sees ciphertext frames only. |
| Push notification metadata leakage           | **Partial**: Apple/Google push servers see the wake notification and any unencrypted user-presentation strings. We deliver opaque ciphertext blobs; rich notification content is decrypted client-side via NSE/Service-Worker. | Disclosed in the privacy notice. |
| Malicious client running on the user's device | **Out of scope.** | If the device is compromised, plaintext is too. |
| Quantum-capable adversary recording today, decrypting later | **Out of scope until post-quantum AEAD/KEX standardize.** Plan to add ML-KEM-768 to the AEAD-alg negotiation when it's IETF-stable. | The `aead_alg` envelope field already supports negotiating new algorithms without a wire break. |
| Username enumeration via the directory       | The server CAN tell whether a username is registered (it has to, to route). Mitigated by allowing pseudonymous identities. | Discord-style "tag" disambiguation may be added later. |
| AES-NI-less ARM softfall timing attacks      | Phase 0 fails loudly when AES-256-GCM cannot be hardware-accelerated. Phase 1 enables XChaCha20-Poly1305 negotiation via the existing `aead_alg` field. | The `aes256gcm_hw_available()` runtime check is the gate. |

## Trust boundaries

```
+----------------+      ciphertext only      +----------------+
|  Client A      | <----------------------> |  Relay server   |
|  (full trust)  |     fb.proto.Envelope    |  (untrusted)    |
+----------------+                          +----------------+
                                                    ^
                                                    | ciphertext only
                                                    v
                                           +----------------+
                                           |  Client B      |
                                           |  (full trust)  |
                                           +----------------+
```

The user trusts only their own devices. Servers, peers, and infrastructure
(DNS, ISP, push providers) are explicitly untrusted.

## External review gate

External cryptographic review is required at the end of Phase 1 before any
non-alpha release. Candidates: NCC Group, Trail of Bits, Cure53. Budget
$20–50k. Server pen-test required before Phase 5 (decentralization
expands the attack surface).
