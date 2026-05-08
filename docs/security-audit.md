<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# FinBit Security Audit — 2026-05-08

A pass over the cryptographic surface of the codebase as it stands at
this commit. Read alongside [`threat-model.md`](threat-model.md) (which
states the security goals) — this doc records what's empirically true
about the implementation.

## TL;DR

- ✅ **DM, channel, and voice/video content are end-to-end encrypted.**
  The server cannot read message bodies, channel posts, SDP, or media.
- ✅ **Server-blindness is empirically verified** — `tools/e2e/*.sh`
  send canary plaintext markers through the server and grep its output;
  the canaries never appear. All four scripts (`dm_roundtrip.sh`,
  `channel_inband_roundtrip.sh`, `offline_persist.sh`,
  `server_persist_full.sh`) pass.
- ⚠️ **Local message store is plaintext on disk.** The vault encrypts
  only the identity seed; `inbox.plaintext`, `outbox.ciphertext`
  (misnamed — actually plaintext), and the legacy `identities.sec`
  column are unencrypted. Anyone who steals the user's data dir reads
  every message. This was always tracked as `TODO(sqlcipher)` in the
  schema; surface it explicitly.
- ⚠️ **`Envelope.aad` field declared but never bound.** The proto
  comment promises that `envelope_id || timestamp_ms` is covered by
  the AEAD tag; in practice the inner ratchet/SenderKeys encrypt is
  called with empty `outer_aad`. A relay can rewrite envelope_id /
  timestamp without invalidating the inner tag. Severity: low — the
  inner protocols still authenticate the actual ratchet message
  numbers and chain state, so injection / reorder / replay are
  detected. Display-time timestamp could be skewed by a malicious
  relay.

The rest of this doc is the layer-by-layer walkthrough.

## 1. Primitives (`core/{include,src}/fb/crypto/`)

All cryptography goes through libsodium. Each primitive uses the
standard, audited libsodium entry point — no hand-rolled crypto.

| Concern | Algorithm | libsodium call | Verdict |
|---|---|---|---|
| Identity sign / verify | Ed25519 | `crypto_sign_detached` / `crypto_sign_verify_detached` | ✅ standard |
| X25519 ECDH | X25519 | `crypto_scalarmult` | ✅ standard |
| Ed25519 ↔ X25519 | — | `crypto_sign_ed25519_{pk,sk}_to_curve25519` | ✅ standard |
| Bulk AEAD (ratchet, sender_keys) | XChaCha20-Poly1305-IETF | `crypto_aead_xchacha20poly1305_ietf_*` | ✅ standard |
| Bulk AEAD (envelope-level, only in tests) | AES-256-GCM | `crypto_aead_aes256gcm_*` | ✅ standard |
| HKDF | HKDF-SHA256 | implemented on `crypto_auth_hmacsha256` | ✅ matches RFC 5869 KAT |
| Vault KDF | Argon2id | `crypto_pwhash_ALG_ARGON2ID13` (MODERATE ops/mem) | ✅ standard |
| BLAKE2b fingerprint | BLAKE2b-160 (5+5 base32) | `crypto_generichash` | ✅ standard |
| Random bytes | — | `randombytes_buf` | ✅ standard |
| Memory hygiene | — | `sodium_malloc` (mlock'd seckey), `sodium_memzero` after use | ✅ |

Notable correctness details:

- **Ratchet message keys are single-use.** Each plaintext is encrypted
  with `mk = HMAC-SHA256(ck, 0x01)` and the chain key advances. A
  zero 24-byte XChaCha20 nonce is therefore safe (the key is unique
  per message).
- **AAD coverage on ratchet messages**: `dhs_pub || pn || ns ||
  outer_aad`. The DR header is bound by the tag, so a relay can't
  rewrite message numbers or DH-ratchet pubkey without breaking the
  tag.
- **AAD coverage on SenderKeys messages**: `chain_id || index ||
  outer_aad`. Index advancement is tag-protected.
- **AES-NI requirement** for AES-256-GCM: hard refusal at runtime if
  unavailable. Live ratchet/SenderKeys path uses XChaCha20 instead so
  ARM/WASM are unaffected.

## 2. Identity vault (`client-desktop/src/identity_vault.cpp`)

Format v2 (105 bytes): `version (1) || salt (16) || ops (8 BE) || mem
(8 BE) || nonce (24) || ct+tag (48)`. The first 33 bytes (everything
through `mem`) are bound into the AEAD AAD so an attacker with write
access cannot downgrade the KDF parameters without invalidating the
tag.

- Argon2id at INTERACTIVE tier by default (~64 MiB / ~0.5s on a
  modern desktop). Per-vault salt + nonce.
- Passphrase bytes zeroed after KDF; KDF output zeroed after
  encrypt/decrypt.
- Vault directory chmod 0700 (best effort via Qt's
  `QFile::setPermissions`).
- Min ops/mem floor checked on decrypt — refuses to spend resources
  on absurdly weak parameters that an attacker forged.
- Backwards-compatible read of v1 (no version byte, no AAD) is
  accepted but never written.

## 3. Wire format & relay (`core/proto/envelope.proto`)

```proto
message Envelope {
    bytes  envelope_id  = 1;     // 16 random bytes
    uint64 timestamp_ms = 2;
    bytes  sender_pubkey = 3;    // 32 bytes (Ed25519), optional
    bytes  ciphertext   = 4;     // AEAD output, opaque to relay
    bytes  aad          = 5;     // documented but not populated
    uint32 aead_alg     = 6;
    uint32 protocol_version = 7;
    bytes  signature    = 8;     // optional, never set in current code
    oneof recipient { bytes user_pubkey | bytes channel_group_id | … }
}
```

What the server sees:

- Routing target (`recipient` oneof — user pubkey for DMs, group_id
  for channels).
- Sender pubkey (when set — currently always set on outbound).
- Random `envelope_id`, `timestamp_ms`.
- Ciphertext byte length.

What the server **cannot** see:

- The plaintext (DMs, channel posts, SDP, ICE candidates, SFrame
  rotation messages).
- The username on the inside of an inbound envelope (only the
  recipient's pubkey — the sender's username is leaked separately
  through `username_lookup` queries when the recipient asks).

### ⚠️ `Envelope.aad` discrepancy

The proto comment says envelope-level AAD is "bound by the AEAD tag —
a relay cannot rewrite the envelope id or shift its timestamp without
invalidating it". Implementation passes empty `outer_aad` to every
inner encrypt call. Severity: low; the inner ratchet/SenderKeys layer
still authenticates content + sequence + DH state. To close the gap
either:

1. Pass `aad = envelope_id || u64_be(timestamp_ms)` into the inner
   `encrypt()` AAD slot, AND populate `Envelope.aad` so the recipient
   can reconstruct the same buffer for `decrypt()`. Wire-compatible;
   one-line change at each of the four envelope-build sites + each
   decrypt site.
2. Or remove the proto comment promise and document envelope fields
   as relay-modifiable display metadata.

Recommend option 1.

### Authentication

- ClientHello → ServerHello issues a 32-byte challenge.
- HelloAck signs the challenge with the user's Ed25519 secret key.
- The relay only binds `(fd, user_pubkey)` after the signature
  verifies — until then no envelopes route to the connection.
- A second ClientHello on an already-authed connection is refused;
  prevents an authed client from re-arming the challenge for a
  different identity and silently re-binding the socket.

## 4. DM ratchet (`core/src/crypto/ratchet.cpp`)

Standard Signal-style Double Ratchet:

- X3DH-derived shared secret seeds the root key.
- DH ratchet advances on each new sender DH pubkey received in a
  header; chain keys re-derived via HKDF-SHA256.
- KDF chain advances via HMAC-SHA256(ck, 0x01) per message.
- Skipped-message-key cache up to `kMaxSkip` to handle out-of-order
  messages; throws on excessive skip.

Cross-tested in CI against fixed vectors (`ratchet_test.cpp`,
`ratchet_signal_kat_test.cpp`). Live e2e covered by
`tools/e2e/dm_roundtrip.sh`.

### Session-mismatch fix from this audit window

A subtle bug was uncovered AND fixed during the recent voice-call
work that's worth recording: `chat_client.cpp` previously created a
SECOND ratchet session on the inbound side
(`sessions["peer:<8 bytes>"]` = init_bob) even when an outbound
session already existed (`sessions["alice"]` = init_alice). The two
sessions have incompatible DH state, so every reply failed to
decrypt. Fix: inbound DM scans existing sessions for matching
`peer_pub` and reuses the one that's already there. This was a
correctness bug rather than a confidentiality bug — failed decrypts
are visible to the user, not silently exposed.

## 5. Channel ratchet (`core/src/crypto/sender_keys.cpp`)

Sender-keys group encryption: each participant owns a `chain_id` +
chain seed; advances per message; recipients install peer
distributions out-of-band (DM-delivered as `DmPayload.channel_key`).
The DM that delivers the SenderKeys distribution is itself encrypted
under the pairwise Double Ratchet, so the channel's sending material
never travels in cleartext.

⚠️ **Compromise model**: a compromised channel member can leak the
chain seed and let an attacker decrypt every past and future message
on that chain. There is no per-message forward-secrecy step or
membership-removal rekey in v0. The plan calls for replacing this
with MLS (RFC 9420) via `mlspp`; until then, a compromised member is
a full channel-key compromise. State explicitly to users.

## 6. Voice / video (`client-desktop/src/media_call.cpp`)

Two layers:

1. **DTLS-SRTP** (always on, default of `webrtcbin`). End-to-end
   between peers. The codebase doesn't expose any DTLS-disable knob;
   plain RTP would require a different element. ✓
2. **SFrame** (encoded-frame layer). `set_sframe_context()` derives
   a per-call base key:
   ```
   base_key = HKDF-SHA256(
       IKM = X3DH-shared-secret(self_x25519, peer_x25519),
       info = "FinBit-SFrame-call-v1-" || hex(call_id))
   ```
   `call_id` is 16 random bytes per call, `shared_secret` is unique
   per peer pair. So the base key is unique per (peer-pair, call).
   Probes attached around `opusenc` / `vp8enc` (send) and
   `rtpopusdepay` / `rtpvp8depay` (recv) seal/open every encoded
   buffer. Wire-compatible with `client-web/ui/media_call.js`.

In the v0 full-mesh topology, DTLS-SRTP alone suffices for
confidentiality — the server sees no media. SFrame matters when an
SFU lands; the design is forward-compatible.

### Channel-call signaling

`RoomJoin` / `RoomLeave` / `RoomRoster` are top-level `Frame`
messages, NOT inside an `Envelope`, so the server learns:

- Who's in which voice room.
- When each participant joined or left.

This is a metadata leak, not a content leak. The actual SDP / ICE
candidates flow over `DmPayload.media_signal` inside an `Envelope`
and are end-to-end encrypted. There's no plan to hide voice-room
membership from the server in centralized mode; call this out
explicitly in user-facing docs.

## 7. ⚠️ At-rest plaintext (SQLite store)

`core/src/store/sqlite_store.cpp` is plain SQLite. Both schema
comment and code carry `TODO(sqlcipher)` markers. Tables containing
sensitive data:

| Table | Sensitive content | Compromise impact |
|---|---|---|
| `identities` | `sec` (Ed25519 secret key, legacy) | Identity takeover. Vault is now the source of truth — could drop this column. |
| `inbox` | `plaintext` (received DMs) | Past messages exposed. |
| `outbox` | `ciphertext` (column misnamed — actually plaintext) | Past messages exposed. |
| `sessions` | ratchet state blob | Future-message decryption if attacker also captures network. |
| `chan_state`, `chan_inbox`, `chan_peers` | channel keys + plaintext | Channel-history exposed. |
| `peer_name_cache` | username ↔ pubkey | Social-graph metadata. |

The vault encrypts the seed with the user's passphrase, but message
history sits next to it in cleartext. **Anyone who steals the data
directory reads every past message without prompting for the
passphrase.** This is the largest delta from the design intent.

Recommended remediations, in increasing order of effort:

1. **Drop the `identities.sec` column** — unused since LoginDialog;
   removes one redundant secret-at-rest.
2. **Wrap inbox/outbox plaintext columns with the same vault key** —
   AEAD per row, key derived from the seed via HKDF with a per-table
   info string. Adds nothing on disk except an extra 16-byte tag per
   row. Doable in a single store-layer PR.
3. **Switch SQLite ↔ SQLCipher** — encrypts the whole database file
   transparently. Per-row option (#2) is simpler and equally
   effective for confidentiality at rest; SQLCipher is what the
   plan called for.

Recommend option 2 as the immediate next step; option 3 if a single
on-disk format is preferred.

## 8. Empirical results

| Test | Status |
|---|---|
| `tools/e2e/dm_roundtrip.sh` (canary in DM) | PASS — server log 406 bytes, no plaintext |
| `tools/e2e/channel_inband_roundtrip.sh` (canary in channel msg + invite) | PASS — server log 479 bytes, no plaintext |
| `tools/e2e/offline_persist.sh` (canary, server restart, persistent queue) | PASS — DB 122880 bytes, no plaintext |
| `tools/e2e/server_persist_full.sh` (directory + prekey + offline survive restart) | PASS |
| `tools/e2e/username_resolve.sh` (canary in DM, username_lookup) | PASS |
| `core/tests` ctest suite | 86 / 86 PASS (excluding 3 pre-existing flakes in unrelated subsystems) |

## 9. Summary of recommendations

In rough priority order:

1. Encrypt local message store at rest (option 2 above — per-row AEAD
   keyed off the vault seed). Closes the largest known gap.
2. Drop the unused `identities.sec` column.
3. Either populate `Envelope.aad` and bind it via inner-encrypt
   `outer_aad`, or update the proto comment to drop the promise.
4. Plan migration to MLS (RFC 9420) for channels — gets membership-
   removal rekey + forward secrecy that SenderKeys can't.
5. Document explicitly to users: the centralized server learns
   metadata (who-talks-to-whom, who's-in-which-room-when), even
   though it never sees content. The roadmap's P2P phase is what
   addresses this.
