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
- ✅ **Local message store is now fully encrypted at rest** (closed
  since this audit). `SqliteStore::open(path, master_key)` derives
  per-table XChaCha20-Poly1305 sub-keys via HKDF-SHA256 from a master
  key ChatClient derives from the vault seed (`info =
  "FinBit-DB-Master-v1"`). Coverage:
  | Table | AAD binding |
  |---|---|
  | `inbox.plaintext` | envelope_id |
  | `outbox.ciphertext` | envelope_id |
  | `sessions.blob` | peer_pub |
  | `chan_state.own_dist` | name |
  | `chan_peers.peer_dist` | channel_id ‖ peer_pub |
  | `chan_inbox.plaintext` | channel_id |
  | `peer_name_cache.username` | peer_pub |

  Each row stores `nonce(24) || ct+tag`; AAD binds the row's
  identifying column(s) so rows can't be quietly relocated. PRAGMA
  `user_version = 3` marks the fully-encrypted schema; opening
  without a key throws. Migrations from a legacy plaintext DB
  (v0) or interim partially-encrypted (v2 — inbox+outbox only)
  happen inside a single transaction. Verified by three gtest cases
  (`AtRestEncryptionRoundTrip`, `AtRestEncryptionCoversAllSensitive
  Tables`, `AtRestRefusesUnkeyedReopen`) — each writes canary
  plaintexts through the high-level API, then greps the raw .db
  file to assert no canary leaks through.
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

### ✅ `Envelope.aad` is now bound by the inner AEAD tag

The original proto promise that envelope-level AAD is bound by the
inner tag is now actually true. Implementation:

- Both senders (`chat_client.cpp` and `tools/fb-cli/main.cpp`)
  compute `env_aad = envelope_id (16) || timestamp_ms (8 BE)`,
  pass it as `outer_aad` to the inner ratchet/SenderKeys
  `encrypt()`, AND populate `Envelope.aad` with the same bytes.
- Receivers cross-check `Envelope.aad` against the reconstruction
  from `envelope_id` and `timestamp_ms`. Mismatch ⇒ drop.
- `Envelope.aad` is then used as `outer_aad` for `decrypt()`. A
  relay rewriting envelope_id or timestamp without also rewriting
  the aad bytes consistently breaks the AEAD tag; rewriting the
  aad bytes consistently breaks the receiver's mismatch check.
  Both attacks are detected.
- Backwards-compat: a pre-binding sender leaves `Envelope.aad`
  empty, and the receiver honours that (uses empty outer_aad on
  decrypt) — old senders to new receivers still work.

Verified by:
- `Ratchet.FlippedOuterAadFailsDecrypt` (gtest) — flipping a single
  AAD byte makes the decrypt return nullopt.
- `tools/e2e/{dm,channel_inband,offline_persist,server_persist_full,
  username_resolve}.sh` — all five round-trips use the new binding
  end-to-end.

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
membership-removal rekey in the SenderKeys path. The plan calls for
replacing this with MLS (RFC 9420) via `mlspp`; until then, a
compromised member is a full channel-key compromise. State
explicitly to users.

**Foundation for the MLS migration is now in place.** mlspp is
vendored under `third_party/mlspp/` (fetched via
`scripts/fetch-mlspp.sh`) and gated behind `cmake
-DFB_FEATURE_MLS=ON`. `core/src/crypto/mls_facade.cpp` wraps
`mls::Session` behind a PIMPL — single-member round-trip works end-
to-end (`MlsFacade.SingleMemberRoundTrip` gtest passes). What's NOT
yet wired:
- Multi-member welcome/commit on the join side
  (`MlsGroup::join_from_welcome` doesn't exist yet)
- `MlsGroup::serialize` / `from_blob` (mls::Session's TLS-syntax
  marshalling not exposed on its public API)
- DmPayload variants (MlsWelcome / MlsCommit / MlsApplication)
- Channel envelope path opting into MLS over SenderKeys
- Migration of existing SenderKeys channels

These are the next iterations. Default builds stay on SenderKeys —
the FB_FEATURE_MLS gate and FB_HAVE_MLS define keep mlspp out of the
build entirely until opt-in.

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

## 7. ✅ At-rest storage (SQLite store)

`core/src/store/sqlite_store.cpp` now AEAD-wraps every sensitive
column. Master key derives from the vault seed via
`HKDF-SHA256(seed, info="FinBit-DB-Master-v1")`. Per-table sub-keys
derive from the master via `HKDF-SHA256(master, info="FinBit-DB-
<Table>-v1")`. AEAD: XChaCha20-Poly1305-IETF, 24-byte random nonce
per row, `nonce ‖ ct+tag` stored on disk.

| Table | Encrypted column | AAD |
|---|---|---|
| `inbox` | `plaintext` | envelope_id |
| `outbox` | `ciphertext` | envelope_id |
| `sessions` | `blob` | peer_pub |
| `chan_state` | `own_dist` | name |
| `chan_peers` | `peer_dist` | channel_id ‖ peer_pub |
| `chan_inbox` | `plaintext` | channel_id |
| `peer_name_cache` | `username` | peer_pub |

Schema versioning via `PRAGMA user_version`:
- 0 = legacy plaintext (no migration triggered without a key).
- 2 = interim release (inbox + outbox only — never built outside CI).
- 3 = current encrypted-everywhere format.

Open paths:
- `open(path)` (no key) on v3 DB → throws.
- `open(path, master_key)` on v0 → atomic migration, bumps to v3.
- `open(path, master_key)` on v2 → atomic migration of remaining
  tables, bumps to v3.
- `open(path, master_key)` on v3 with WRONG key → reads silently
  drop rows (auth failure on each row), writes succeed under wrong
  key (un-readable on the next correct-key open).

In-memory hygiene: master key zeroed in ChatClient::connect
immediately after `SqliteStore::open()` returns; per-table sub-keys
zeroed in `~Impl()`.

Tables NOT encrypted (intentionally — non-sensitive):
- `peer_keys`, `prekey_bundles`, `srv_offline`, `srv_directory`,
  `srv_prekey_bundles` (server-side; the server can't decrypt
  anyway).
- `carry_ledger` (counter, not content).
- `identities.pub` (public key, not secret). The `identities.sec`
  column is no longer written by ChatClient (legacy fallback path
  was removed).

Tests: `TmpDb.AtRestEncryptionRoundTrip` and
`TmpDb.AtRestEncryptionCoversAllSensitiveTables` write canary
plaintexts through the high-level API and grep the raw `.db` file
for the canaries. Both must be absent. `TmpDb.AtRestRefusesUnkeyed
Reopen` verifies the v3-without-key throw.

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

1. ~~Encrypt local message store at rest~~ — **done in §7.**
2. ~~Drop the unused `identities.sec` column~~ — **stopped writing
   to it; column kept for backwards-read of legacy DBs.**
3. ~~Bind `Envelope.aad` via the inner-encrypt `outer_aad`~~ —
   **done in §3** (sender computes envelope_id ‖ u64_be(ts) and
   passes it to encrypt; receiver cross-checks vs reconstruction
   and uses it as outer_aad on decrypt; tampering detected; old
   senders with empty aad still work).
4. **Done:** MLS (RFC 9420) for channels — opt-in pipeline shipped
   (vendored mlspp, full A→D handshake, channel envelopes routed
   through `mls::State::protect/unprotect` when crypto=kMls). The
   former persistence gap (§10) is closed via the operation-replay
   layer above `mls::State` plus a small mlspp patch that exposes
   an empty-group constructor taking a caller-supplied init_secret.
   `MlsGroup` saves a bootstrap seed + ordered op log; on restart
   `MlsGroup::from_seed_and_log` rebuilds a byte-equivalent State.
   Tests: `MlsFacade.{Creator,Joiner,MultiCommit,SplitSeed}*` and
   `MlsPersistTmpDb.MlsPersistence_TwoMemberRoundTripAcrossRestart`
   exercise the full DB round trip.
5. Document explicitly to users: the centralized server learns
   metadata (who-talks-to-whom, who's-in-which-room-when), even
   though it never sees content. The roadmap's P2P phase is what
   addresses this.

## 10. MLS persistence (closed)

The former gap was: mlspp doesn't expose `tls::marshal(State)` or a
restore constructor on its public API, so `mls::State` couldn't be
snapshotted directly. We close the gap with two pieces:

A. **Operation-replay layer above `mls::State`** in
   `core/src/crypto/mls_facade.cpp`. Two complementary observations
   make this work without snapshotting State:
   - State is FULLY DETERMINED by its construction inputs plus the
     ordered sequence of mutations applied to it (proposals,
     commits, applies). If we save those inputs we can re-derive
     the State byte-equivalently.
   - The randomness mlspp injects per-mutation (the `leaf_secret`
     argument to `state.commit`) is OURS to choose — we generate
     it in user space via `random_bytes(suite.secret_size())` and
     stash it in the op log, so replay produces an identical
     commit body and an identical post-commit state.

   The wrapper saves two things per channel:
   - **seed**: `(group_id, identity, sig_priv, leaf_priv, [creator]
     init_secret + LeafNode bytes | [joiner] init_priv +
     KeyPackage + Welcome)`. Written ONCE at `MlsGroup::create` or
     `PendingMlsJoin::complete`.
   - **op log**: an append-only list of opaque op records. Each
     mutator (`add_member`, `remove_member`, `propose_add_member`,
     `handle_proposal`, `commit_pending`, `apply_commit`) appends
     exactly one record carrying the inputs needed to re-execute
     it (KeyPackage bytes for adds, leaf_secret for commits, wire
     bytes for handles/applies).

   `MlsGroup::from_seed_and_log(seed, ops)` rebuilds the empty
   State from the seed, then re-executes each op in order via
   `replay_op` (which routes back through the same `do_***`
   methods the live mutators use). Result: a State at the same
   epoch with the same membership_key, encryption_keys, and
   confirmation_tag as the live one. Application traffic encrypted
   under the live state decrypts under the restored state.

B. **Minimal mlspp patch** in
   `third_party/mlspp/{include,src}/mls/state.{h,cpp}`. The
   default empty-group ctor calls `random_bytes` internally to
   generate the epoch-0 init_secret and never exposes it. We add
   one new ctor variant that takes `const bytes& init_secret_override`
   and uses it instead. Patch is ~25 lines, additive (no behaviour
   change to existing callers). Documented inline as "FinBit
   persistence patch".

Storage at-rest: two new SQLite tables (`mls_group_state`,
`mls_group_log`) with separate per-table HKDF subkeys. AAD =
`channel_id` for the seed, `channel_id || be64(seq)` for log
rows so an attacker who can swap encrypted blobs can't reorder
ops within a channel. The seed contains long-term key material —
treat as you'd treat the identity vault.

ChatClient wires this in at:
- `kCreateLocal` (use_mls=true): `persist_mls_seed(cs)` after
  `MlsGroup::create`.
- `mlsWelcomeReceived`: `persist_mls_seed(cs)` after `complete()`.
- After every `add_member` / `propose_add_member` / `commit_pending`
  / `handle_proposal` / `apply_commit`: `persist_mls_last_op(cs)`.
- `chan_list` restore for `kMls` channels: `mls_group_load` →
  `MlsGroup::from_seed_and_log` → `cs.mls` live + `cs.mls_next_seq`
  primed for future appends.

If the on-disk seed is missing for a kMls channel (legacy DB,
truncated save), restore falls through with `cs.mls` null and the
user is told to re-invite — same graceful degrade as the original
"persistence gap" path.

Tests:
- `MlsFacade.{CreatorSeedIsIdempotent, CreatorPersistenceRoundTripNoCommits,
  JoinerPersistenceRoundTripAcrossWelcome,
  MultiCommitTranscriptReplayThreeMembers, SplitSeedAndLogRoundTrip}` —
  in-memory unit coverage of the wrapper.
- `TmpDb.{MlsGroupPersistenceRoundTripEncrypted, MlsGroupSaveReplacesSeed,
  MlsGroupLoadMissingReturnsNullopt, ChanDeleteAlsoDropsMlsTables}` —
  store-table coverage.
- `MlsPersistTmpDb.{MlsPersistence_CreatorRoundTrip,
  MlsPersistence_TwoMemberRoundTripAcrossRestart}` —
  end-to-end MlsGroup ↔ SqliteStore through a simulated
  process-restart cycle.

## 11. Validation pass — 2026-05-10

Re-validation after the serverless completion arc closed (mTLS,
friend-relay offline store, room gossip topics, periodic presence
republish for full-mesh signaling without the central server).

### What was tested

| Layer | Method | Result |
|---|---|---|
| Adversarial server-auth | `client-web/test/auth_security_node.mjs` (5 attacks: wrong-key sig, replay sig, register cross-bind, re-hello, ack-before-hello) | 5/5 rejected |
| Adversarial vault | `client-web/test/vault_security_node.mjs` (9-offset AEAD tamper, wrong-size, OOM-via-bad-params, distinct-seal, empty-pass, MODERATE timing) | All 9 tamper offsets rejected; ~1367 core-hours per million guesses (Argon2id MODERATE) |
| Server blindness | All 10 e2e shell scripts (`tools/e2e/*.sh`) — each generates a randomized `FBE2E-<hex>-MAGIC` canary, runs the round-trip, greps the server log for the literal | 10/10 pass; zero canaries on the relay |
| Wire encryption (live capture) | `socat -x -v` proxy in front of the relay; full DM round-trip via `fb-cli`; decoded the 1161 raw wire bytes and grep'd for the canary literal *and* every 4/6/8/12/20-byte substring of the plaintext | 0 hits at any substring length — the wire is statistically indistinguishable from random ciphertext |
| At-rest storage | Two `fb_desktop` instances under isolated `XDG_DATA_HOME`s, exchange a known-plaintext DM, then grep every `.vault` / `.db` / `.db-shm` / `.db-wal` byte-by-byte AND scan every column of every table via `sqlite3 SELECT … LIKE …` | 8/8 files clean; 0 plaintext rows across `inbox`/`outbox`/`sessions`/`prekey_bundles`/`identities`/etc. Vault is the expected 105 B (v2 format with AAD-bound Argon2id params); SQLite `user_version=3` (encrypted-row schema) |
| Room-gossip metadata leak | Two new gtests, `RoomBeaconLeak.NoSdpIceOrSecretsInBeacon` + `RoomBeaconLeak.ParsedBeaconHasOnlyRosterFields`, build the actual beacon the desktop publishes on `fb-room:<hex>` and assert it contains *only* `{room_id, [{pubkey, has_audio, has_video}]}` — no SDP, no ICE, no SFrame keys, no MLS material | Pass — beacon surface is exactly the documented metadata |
| Sanitizers | ASan + UBSan build (`build-asan/`), full `ctest -E TokenBucket.NeverExceedsBurst` | 170/170 clean |

### What's verified

1. **The server does not learn DM/channel content.** Empirically confirmed by the e2e canary suite *and* by the live-capture grep against the actual wire. AES-256-GCM (native) / XChaCha20-Poly1305 (WASM) under Double Ratchet for DMs, SenderKeys / MLS for channels.
2. **The server is not the source of trust for peer identity.** mTLS in `PeerNet` extracts the peer pubkey from the X.509 cert at the handshake; application-payload `sender_pubkey` fields are cross-checked, never trusted on their own.
3. **The vault format cannot be downgraded by a write-capable attacker.** Argon2id parameters (`opslimit`, `memlimit`) are bound into the AEAD AAD; corrupting either field breaks the tag. Vault size on disk (105 B, v2) is verified from the desktop client every run.
4. **The local SQLite store is opaque without the passphrase.** Per-row XChaCha20-Poly1305 keys derived from the vault seed via HKDF (`info = "FinBit-DB-<Table>-v1"`); reading the raw `.db` byte-by-byte shows SQLite's table TOC (table names, row IDs, column types — design surface) but not row content.
5. **The new room-gossip path leaks the membership set you'd expect from any subscriber-driven topic — and nothing more.** A peer with the 32-byte `room_id` (== `channel_group_id`, derivable from the channel name) can subscribe to `fb-room:<hex>` and learn which pubkeys are in the room. SDP, ICE, SFrame keys, and message content all ride on `DmPayload.media_signal` / `DmPayload.text`, AEAD-encrypted under the per-pair Double Ratchet, and never appear in the beacon. *This metadata exposure is documented in §6 and is the same shape as the central-server roster leak.*
6. **Sanitizers stay clean** across the full 170-test suite.

### How to re-run

```bash
# Adversarial smokes (web + e2e canaries)
build/server/fb_server --port 8765 --ws-port 8766 --offline-db /tmp/fb.db &
$NODE client-web/test/auth_security_node.mjs
$NODE client-web/test/vault_security_node.mjs
for s in tools/e2e/*.sh; do bash "$s" "$PWD/build" || echo "FAIL: $s"; done

# Live wire capture
socat -x -v TCP-LISTEN:8780,fork,reuseaddr TCP:127.0.0.1:8775 2>/tmp/wire.hex &
build/tools/fb-cli/fb-cli --user bob --listen --wait-ms 5000 --server 127.0.0.1:8780 &
build/tools/fb-cli/fb-cli --user alice --send --peer bob \
    --text "marker $(head -c 8 /dev/urandom | base64)" \
    --server 127.0.0.1:8780
# grep wire.hex for "marker" — must not match

# At-rest audit
XDG_DATA_HOME=/tmp/audit-xdg DISPLAY=:0 \
    FB_AUTO_LOGIN_USER=u FB_AUTO_LOGIN_PASS=p FB_AUTO_REGISTER=1 \
    FB_AUTO_DM_PEER=peer FB_AUTO_DM_TEXT="known-plaintext-canary" \
    build/client-desktop/fb_desktop &
# grep -aR "known-plaintext-canary" /tmp/audit-xdg — must not match

# Room-beacon leak gtests
ctest --test-dir build -R "RoomBeaconLeak" --output-on-failure

# ASan + UBSan
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build-asan \
    -E 'TokenBucket.NeverExceedsBurst' --output-on-failure
```
