# FinBit ops runbook

Operational procedures for running the FinBit relay server in production.
This is a living document; expand as Phase 1+ subsystems come online.

## Deploy checklist

1. **Replace the placeholder URL.**
   Edit `core/include/fb/config/build_config.hpp` —
   `kDefaultServerUrl` must point at your production server before
   shipping any binary.

2. **Pick a sensible bind address.**
   Production: bind to a private interface, terminate TLS at a reverse
   proxy (nginx / Caddy / Envoy). The relay protocol itself is
   plaintext-on-the-wire because the message bodies are already
   E2E-encrypted, but TLS at the relay boundary defeats casual passive
   eavesdroppers from learning who's online.

3. **Provision per-pubkey rate-limit defaults** appropriate to your user
   base. The compiled-in defaults (50 KB/s / 500 KB burst) are fine for
   text-only Phase 0; voice/video in Phase 2 will need an order of
   magnitude more.

4. **Stand up offline-message storage.** Phase 0's relay holds offline
   envelopes in RAM (lost on restart). Before any user-facing rollout,
   move `Relay::offline_` into SQLite (or PostgreSQL) so a rolling
   restart doesn't drop messages.

5. **Plan capacity.** uWS-style relays handle ~100k concurrent idle WS
   connections per 4-core box. The Phase-0 epoll relay should hit ~5k.
   Voice/video (Phase 2+) requires horizontal SFU scaling — Kubernetes
   from Phase 2 onward.

## Run

```bash
fb_server --host 0.0.0.0 --port 8765
```

Logs go to stderr. None of them include envelope ciphertext or any field
that could reveal plaintext (see `tools/e2e/dm_roundtrip.sh` for the
verification).

## Smoke test after deploy

```bash
tools/e2e/dm_roundtrip.sh /opt/finbit/build
```

The script spins up two CLI peers against a fresh server instance,
exchanges a DM with a random plaintext marker, and asserts the marker
never appears in the server logs. Run on every deploy.

## Failure modes

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Clients get `RATE_EXCEEDED` on first envelope | Token-bucket defaults too low for your media | Recompile with higher `fb::config::ratelimit::*` defaults |
| Relay restart drops queued offline messages | Phase 0 limitation: offline queue is in-memory | Roll forward to the SQLite-backed queue (Phase 1) |
| `[server] AES-256-GCM hardware acceleration unavailable` | Server CPU lacks AES-NI / ARMv8 crypto | Pin server pool to AES-NI hardware until XChaCha20-Poly1305 negotiation lands (Phase 1) |
| Server hits fd limit | Many concurrent connections | `ulimit -n 65536` in the systemd unit; consider sharding |

## Phase 5 (decentralization) ops

When transitioning to P2P at the 10k-user threshold:
- The relay becomes a bootstrap node + offline-message store only.
- Run several geographically dispersed bootstrap nodes with stable IPs
  baked into the client's `kDefaultServerUrl` (or a list resolved at
  startup).
- Carry-credit ledger queries become a hot path; SQLite is fine to
  ~100k tracked counterparties; beyond that swap for a key-value store.
