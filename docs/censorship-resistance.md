# FinBit — Censorship-Resistance Architecture

> Status: living doc — Tier 1 (DoH bootstrap) shipped 2026-05-19;
> Tier 2 (ALPN + native WSS) shipped 2026-05-20.
> Tiers 3–4 tracked in [`docs/roadmap.md`](roadmap.md).

## 1. Threat model

We assume an adversary who controls some portion of the network path
between the client and any FinBit peer. The adversary can:

| Capability | In scope? |
| --- | --- |
| Block individual IPs / IP ranges (BGP, firewall) | Yes |
| Block individual TCP/UDP ports | Yes |
| Block individual DNS names (DNS hijacking / NXDOMAIN injection) | Yes |
| Block plain DNS (UDP/53, TCP/53) entirely | Yes |
| Inspect TLS SNI and Server Name Indication metadata | Yes |
| Perform deep-packet-inspection on plaintext (HTTP, IRC, etc.) | Yes |
| MITM TLS via a CA the client trusts (rogue root) | Out of scope — assume system CA bundle is intact |
| Block ALL outbound HTTPS (TCP/443) | Out of scope — would also break the entire web |
| Coerce a hosted server operator via legal process | Yes (covered by zero-knowledge server design) |
| Compromise the user's device / install a keylogger | Out of scope |
| Break AES-256-GCM, Ed25519, or X25519 | Out of scope |

Our design goal is: **a user behind a censoring firewall that allows
normal HTTPS browsing must be able to send and receive FinBit
messages without the operator of that firewall being able to identify
the traffic as FinBit by network signature alone.**

We do NOT claim to defeat operator-level TLS fingerprinting (JA3 /
JA3S) at v1. That's a Tier 4 enhancement (uTLS-style ClientHello
mimicry).

## 2. Defense tiers

### Tier 1 — DNS-over-HTTPS (DoH) bootstrap  ✅ shipped 2026-05-19

**Problem.** A new client needs to learn at least one peer address
to bootstrap into the DHT and gossip layer. Doing this over plain DNS
(`dig _finbit.example.com TXT`) leaks the lookup to every DNS resolver
on the path AND can be blackholed by an upstream filter.

**Solution.** `core/net/doh_resolver.{hpp,cpp}` resolves TXT records
under the `_finbit.<host>` label via DNS-over-HTTPS to one of the
public DoH resolvers:

- `https://cloudflare-dns.com/dns-query` (primary)
- `https://dns.google/resolve`
- `https://dns.quad9.net/dns-query`

Each request is a normal HTTPS GET to a well-known, heavily-used
domain. A passive observer sees only TLS-on-443 to Cloudflare/Google
— indistinguishable from a browser fetching a website.

Wire format for TXT records (one per peer; multiple records under the
same name are merged):

```
_finbit.example.com  300  IN  TXT  "fb1 ed25519:<hex32> wss://relay.example.com:443[#<sha256fp>]"
```

The `fb1 ` magic prefix future-proofs the record format; unknown
prefixes are silently skipped, so operators can mix FinBit records
with unrelated TXT records on the same name.

**Activation.** `FB_BOOTSTRAP_DOH=<query-name>` env var.
`load_default_bootstrap_all()` (now called by `chat_client.cpp`)
merges DoH results with the file-based bootstrap (if any).

**Bypass cost for a censor.** To block FinBit bootstrap an adversary
must block ALL public DoH resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) —
which breaks DoH for every browser and OS that ships DoH-on-by-default
(Firefox, Chrome, iOS, recent Android, recent Windows). The
collateral damage is large; in most jurisdictions this is a
political non-starter.

**Residual risks.**
1. **TLS fingerprinting.** OpenSSL's ClientHello is identifiable as
   "not-a-browser" by JA3 fingerprinting. A sophisticated censor (DPI
   appliance) could block our DoH requests specifically. Mitigation:
   Tier 4 uTLS mimicry — defer to v1.3+.
2. **IP blocking of 1.1.1.1.** Easier to mitigate than DNS blocking,
   harder than blocking a single FinBit-branded host. The fallback
   chain (Cloudflare → Google → Quad9) means three different anycast
   networks must be blocked simultaneously.
3. **Compelled-disclosure of the TXT records.** A `dig @1.1.1.1
   _finbit.example.com TXT` from an investigator reveals the
   bootstrap peer list. This is acceptable because the peer list is
   already public — the bootstrap addresses are designed to be
   directly dialled by anyone.

### Tier 2 — TLS-on-443 transport mimicry  ✅ partial (ALPN + native WSS shipped 2026-05-20)

**Problem.** Even with a DoH bootstrap, the actual peer transport was
recognisably non-browser TLS. Two concrete tells existed before this
work:

1. **No ALPN.** A browser ALWAYS advertises ALPN (`h2,http/1.1`) in
   its ClientHello. FinBit's `TlsClient` sent none — a one-bit
   classifier ("has ALPN extension?") flagged every connection.
2. **No HTTP upgrade.** The native client spoke raw length-prefixed
   protobuf immediately after the TLS handshake. It never performed
   the `GET / HTTP/1.1` + `Upgrade: websocket` dance a browser does
   over `wss://`. Only browsers (hitting the server's `--tls-port`
   WSS endpoint) looked like WSS; the native desktop/CLI client did
   not.

**What shipped.**

- **ALPN on both sides.** `TlsClientOptions::alpn_protocols` defaults
  to `{"http/1.1"}` and is wired through `SSL_set_alpn_protos`. The
  server registers an `alpn_select_cb` that selects `http/1.1`
  whenever the client offers it (even if the client also offered
  `h2`). Verified at the wire level with `openssl s_client -alpn`:

  | Client offers | Server selects |
  | --- | --- |
  | `h2,http/1.1` (browser-like) | `http/1.1` |
  | `http/1.1` | `http/1.1` |
  | `h2` only | *(declines — we don't speak h2)* |

  We deliberately do **not** advertise `h2` from the client, because
  we genuinely speak HTTP/1.1 on top (the WS upgrade and the DoH GET
  are both HTTP/1.1). Offering a protocol we can't speak would break
  against a third-party server (e.g. a public DoH endpoint) that
  selected it. Closing this gap (advertise `h2` for fingerprint
  realism without speaking it) belongs with Tier 4 uTLS.

- **Native WebSocket client.** `fb::net::ws` gained the client half it
  was missing: `build_client_upgrade_request` (browser-like
  `GET / HTTP/1.1` with a random `Sec-WebSocket-Key`, `Host`,
  `Origin`, `User-Agent`), `ClientHandshakeParser` (validates the 101
  + `Sec-WebSocket-Accept`), and `build_client_binary_frame` (masked
  per RFC 6455 §5.3). `FrameParser` is now direction-aware
  (`expect_masked`) so the client parses the server's unmasked frames.

- **`fb-cli --wss`.** Drives the full path: TLS → WS upgrade → masked
  WS binary frames carrying one serialized `Frame` each. Proven end to
  end by `tools/e2e/wss_native_dm_roundtrip.sh` (server `--tls-port`,
  two `--wss` peers, DM round-trips, server log stays blind).

**Remaining Tier-2 follow-up.**
- Wire the **desktop client** (`chat_client.cpp`) and **PeerNet**
  (`peer_net.cpp`) onto the same `--wss` path. They currently dial
  `wss://` addresses as "TLS + raw frames"; the building blocks
  (`fb::net::ws` client helpers) are now in place, so this is
  call-site adoption, not new protocol work.
- HTTP-Upgrade `Connection: Upgrade` is already emitted; a future pass
  can add believable extra headers / cookie to defeat L7 template
  matching.

### Tier 3 — Decoy / domain-fronting  🚧 planned

**Problem.** Tier 2 still relies on the censor not knowing the IP of
any FinBit relay. Once IPs are leaked (compelled disclosure, scraping
TXT records, etc.), they can be IP-blocked.

**Plan.**
- Optionally route the WebSocket upgrade through a CDN that supports
  domain-fronting (Cloudflare Workers, Fastly, CloudFront). The
  client connects to `cdn.cloudflare.com:443` with SNI =
  `random-customer.cloudflare.com` and the actual destination encoded
  in the request body.
- This DOES require either (a) operator-paid CDN account, or (b) a
  community-run pool. Defer scope decisions to v2.

### Tier 4 — uTLS / browser ClientHello mimicry  🚧 planned

**Problem.** JA3 fingerprinting tells a DPI appliance "this is
OpenSSL 3.x, not Chrome" even when SNI and ALPN look right.

**Plan.** Vendor [refraction-networking/utls] (Go) — eventually port
or wrap. Or use BoringSSL with custom cipher-list / extension ordering
patches. Generates ClientHello bytes byte-for-byte identical to a
Chrome / Firefox build pinned to a specific milestone.

This is the most-invasive defense — replacing the OpenSSL handshake
layer — so it's deliberately last.

## 3. What still leaks

Even with all four tiers, a sufficiently capable adversary can
identify FinBit traffic by:

- **Traffic timing.** Voice/video calls produce distinctive 20ms
  Opus frame cadence; no transport mimicry hides this.
- **Volume distribution.** A user who never sends a message larger
  than 64 KiB but receives a constant 50 KiB/s stream is not browsing
  the web. Padding helps, mesh-routing helps more.
- **Endpoint correlation.** A user who connects to `1.1.1.1` (DoH)
  immediately followed by an unfamiliar `cloudflare.com` IP looks
  suspicious. Domain-fronting through a popular destination mitigates
  this.

Censorship resistance is a defense-in-depth game. Tier 1 raises the
floor; each subsequent tier raises it further. None of them
individually defeats a nation-state adversary with a dedicated team
— but the goal is to make FinBit not worth singling out.

## 4. Roadmap

| Tier | Status | Code | Tracking |
| --- | --- | --- | --- |
| 1. DoH bootstrap | ✅ shipped | `core/net/doh_resolver.*` | done |
| 2. TLS-on-443 transport mimicry | ✅ partial | ALPN (`tls_client.cpp` + server `alpn_select_cb`) + native WSS (`fb::net::ws` client + `fb-cli --wss`) shipped; desktop/PeerNet adoption pending | done / follow-up |
| 3. Domain-fronting | 🔲 planned | — | v2 |
| 4. uTLS ClientHello mimicry | 🔲 planned | — | v2 |

## 5. References

- Cloudflare DoH spec: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
- Google DNS-over-HTTPS JSON API: https://developers.google.com/speed/public-dns/docs/doh/json
- JA3 fingerprinting: https://github.com/salesforce/ja3
- uTLS (Go): https://github.com/refraction-networking/utls
- RFC 8484 (DoH): https://datatracker.ietf.org/doc/html/rfc8484
- RFC 1035 §3.3.14 (TXT record format): https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
