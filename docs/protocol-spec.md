# FinBit wire protocol — v0.1 (Phase 0)

This document is normative for the Phase 0 build. Phase 1 will extend it
(MLS group messages, prekey signatures, header encryption); the existing
fields will not change shape.

## Framing

Each TCP segment carries a sequence of length-prefixed frames:

```
[u32 BE length][N bytes payload]
```

Maximum payload size is 8 MiB (`fb::net::kMaxFrameBytes`). Larger frames
are a protocol violation; the receiver MUST close the connection.

The payload bytes are a serialized `fb.proto.Frame` protobuf.

## Top-level frame

`fb.proto.Frame` is a `oneof` over the following bodies:

| Field | Number | Direction | Purpose |
|-------|--------|-----------|---------|
| `envelope` | 1 | both ways | The single E2E-encrypted message unit |
| `batch` | 2 | server → client | Bulk delivery on reconnect |
| `control` | 3 | server → client | Rate-limit, error, retry-after |
| `hello` | 4 | client → server | First frame on a connection |
| `server_hello` | 5 | server → client | Response to `hello` |
| `key_upload` | 6 | client → server | Publish a `PreKeyBundle` |
| `key_fetch` | 7 | client → server | Request a peer's bundle |
| `key_fetch_resp` | 8 | server → client | Bundle answer |
| `register_req` | 9 | client → server | Claim a username |
| `register_resp` | 10 | server → client | Registration result |

## Envelope

The `Envelope` is the only thing the relay reads. Fields:

```
Envelope {
  bytes  envelope_id      = 1;   // 16 bytes random
  uint64 timestamp_ms     = 2;
  bytes  sender_pubkey    = 3;   // 32 bytes Ed25519, optional
  bytes  ciphertext       = 4;   // opaque AEAD output
  bytes  aad              = 5;   // envelope_id || ts (BE u64)
  uint32 aead_alg         = 6;   // 1 = AES-256-GCM
  uint32 protocol_version = 7;
  bytes  signature        = 8;   // optional Ed25519
  oneof recipient {
    bytes user_pubkey       = 16;  // DM
    bytes channel_group_id  = 17;  // MLS group (Phase 1)
    bytes broadcast_topic   = 18;  // gossipsub topic (Phase 5)
  }
}
```

The relay routes by `recipient`, persists offline if the recipient is
absent, and never reads `ciphertext` or `aad`.

## Inner messages (after AEAD decryption)

Phase 0 supports one inner message type for DMs:

### RatchetMessage

```
RatchetMessage {
  bytes  header_dh_pub = 1;  // 32-byte X25519 send-chain public key
  uint32 pn            = 2;  // length of previous send chain
  uint32 n             = 3;  // index in current send chain
  bytes  ciphertext    = 4;  // AES-256-GCM(plaintext, key=mk, nonce=0,
                             //              aad = header_dh_pub || pn || n
                             //                    || outer_aad)
}
```

The inner ciphertext is what travels in `Envelope.ciphertext`. The Double
Ratchet's symmetric chain ensures `mk` is fresh for every message; the
fixed all-zero AEAD nonce is therefore safe.

## Pre-key bundle (Noise_IK / X3DH bootstrap)

```
PreKeyBundle {
  bytes  identity_pubkey      = 1;  // 32 bytes Ed25519
  bytes  signed_prekey        = 2;  // 32 bytes X25519
  bytes  signed_prekey_sig    = 3;  // Ed25519 signature
  bytes  one_time_prekey      = 4;  // 32 bytes X25519, consumed on use
  uint32 one_time_prekey_id   = 5;
  uint64 published_at_ms      = 6;
}
```

Phase 0 uses a simplified flow: the X25519 key is derived from the
identity Ed25519 key via libsodium's `crypto_sign_ed25519_*_to_curve25519`,
the OPK and SPK signature are not yet produced. Phase 1 adds both and the
flow becomes proper X3DH.

## Shared-secret derivation (Phase 0 simplified)

```
SK = HKDF-SHA256(
    salt = nil,
    ikm  = X25519(my_x_priv, peer_x_pub),
    info = "FinBit-X3DH-v0",
    L    = 32,
)
```

Both Alice and Bob compute the same `SK`; Alice initializes the Double
Ratchet with `init_alice(SK, peer_x_pub)`, Bob with
`init_bob(SK, my_x_priv, my_x_pub)`.

## Rate limiting

The server applies a per-`sender_pubkey` token bucket on inbound
envelopes. Defaults from `fb::config::ratelimit::*`:

- Sustained: 50 KB/s
- Burst:     500 KB

Over-quota envelopes are dropped with a `ControlMessage{ code =
RATE_EXCEEDED, in_reply_to_envelope_id, retry_after_ms }`.

## Phase transitions

The wire format does not change between centralized and P2P modes. In
centralized mode the client sends `Envelope`s over WebSocket/TCP to the
relay. In P2P mode the same `Envelope`s flow over libp2p streams to peers
and gossipsub fans out for channels. The server is then optional
(offline + bootstrap only).
