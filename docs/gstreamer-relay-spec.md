<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Implementation spec — GStreamer peer media-relay (Lever B muscle)

> Scope: the media-plane half of Lever B (`docs/serverless-group-calls.md`).
> The **election + topology brain** already ships (`fb::media::elect_forwarder`
> / `plan_topology`, `uplink_class` on `RoomJoin`/`RoomMember`, computed +
> logged in `chat_client`). This spec is what to build **on a box with audio
> hardware and ≥3 endpoints** so an elected peer can actually relay audio to
> ~24 — staying end-to-end encrypted and serverless.
>
> Status: not started. Audio-only first; video/simulcast is Lever C.

## 0. The one invariant: the forwarder never decodes

A forwarder relays media for peers **without holding the SFrame key**. It
terminates DTLS-SRTP (it *is* a WebRTC peer, so it sees RTP), but the RTP
*payload* is an SFrame-sealed Opus frame the publisher sealed end-to-end.
The forwarder **re-payloads** (`rtpopusdepay → rtpopuspay`) and forwards;
it **must never instantiate `opusdec`** and must never be given an SFrame
key. Everything below preserves this.

Consequence: a sender's frames fan out to *every* receiver, so all
receivers must share the key for that sender — today's **pairwise**
SFrame key (X3DH(pair) ‖ call_id) does **not** work in a forwarded room.
See §2 (group keying) — this is the prerequisite, not an afterthought.

## 1. Components

| Piece | Where | Reuses |
| --- | --- | --- |
| `RoomLeafCall` | new, client-desktop | the send-branch builder in `media_call.cpp` (mic → `volume` → `opusenc dtx` → `rtpopuspay`) + `sframe_seal_probe` |
| `RoomForwarder` | new, client-desktop | one `webrtcbin` per leaf + a depay→repay bridge; **no decoder** |
| orchestration | `ChatClient` | `elect_forwarder` / `plan_topology` (shipped); `active_voice_rooms`, roster handling |
| signalling | existing protos | `RoomOffer` / `RoomAnswer` / `RoomIce` (reserved) over the relay |
| group key | `core/crypto` + `fb::media::sframe` | SFrame wire format `[u32 epoch][u64 ctr][AES-256-GCM]` (unchanged) |

Leaves and the forwarder both run on participants; which role a node
plays comes straight from `plan_topology(...).i_am_forwarder`.

## 2. Group SFrame keying (do this first)

Replace the per-pair call key with a **per-room secret** from which every
member derives a **per-sender** key:

```
room_secret  = 32 bytes, shared by all room members, rotated per epoch
K_sender     = HKDF-SHA256(room_secret,
                           info = "FinBit-SFrame-room-v1" ‖ sender_pubkey ‖ be32(epoch),
                           L = 32)
```

- A publisher seals its frames with `K_self`. Any receiver derives
  `K_sender` for that publisher from the shared `room_secret` — so the
  blind forwarder can fan one sealed stream to all.
- **Distribution of `room_secret`:**
  - **MLS channels:** export it from the group — `room_secret =
    MlsGroup::export_secret("FinBit-room-sframe", epoch)`. Free rotation
    on every commit; removed members can't derive new-epoch keys.
  - **SenderKeys channels:** the room creator picks a random
    `room_secret` and distributes it over the existing ratchet via a new
    `DmPayload` variant (`RoomKey{room_id, epoch, secret}`), or piggybacks
    on `ChannelKeyDistribution`. Rotate (new random + redistribute) on
    join/leave.
- **Epoch** = `RoomRoster.sframe_epoch` (already in the proto, already
  bumped server-side on membership change). Wire it into the SFrame
  header's epoch field (already present in the on-wire format) so a
  mid-call rotation is unambiguous; receivers keep the previous epoch's
  key briefly to decode in-flight frames.

`fb::media::sframe` stays as-is; only the key-derivation input changes.
The per-sender derivation **ships now** as
`fb::media::derive_room_sframe_key(room_secret, sender_pubkey, epoch)`
(pure, unit-tested — see `SFrameRoomKey.*`). `media_call.cpp`'s
`set_sframe_context` will gain a "room mode" that seals with `K_self` and
opens each inbound pad with the per-sender `K_sender` (the single-base_key
1:1 ctx must split into seal-key + per-sender open-keys). The room_secret
is now sourced for both channel types (MLS exporter / distributed RoomKey,
both shipped — §9 item 1); the remaining probe-side wiring is **fully
specified in §6A**.

## 3. Signalling flow (per leaf joining)

All control rides the existing relay/ratchet; SDP/ICE never hits the
relay in cleartext (same as 1:1 — `DmPayload.media_signal`, or the
room-scoped `RoomOffer/RoomAnswer/RoomIce` to the forwarder).

```
1. Everyone sends RoomJoin{uplink_class}; server fans out RoomRoster.
2. Each node runs elect_forwarder(roster) → same forwarder F (shipped).
3. plan_topology: F.i_am_forwarder; leaves get dial = [F].
4. Leaf L → F:  RoomOffer{room_id, sdp}   (offer: 1 sendonly audio = L's
                mic; recvonly slots for the other members)
   F → L:       RoomAnswer{room_id, sdp}
   both:        RoomIce{...} trickle until ICE connected.
5. F adds L's inbound stream to the relay graph (§4) and adds an outbound
   track of L to every existing leaf's PeerConnection (renegotiate — §5).
6. On L leave / F leave: roster changes → re-elect; if F changed, leaves
   tear down and re-offer to the new F. Epoch bumps → rekey (§2).
```

Routing of `RoomOffer/Answer/Ice` to the forwarder: address them to the
forwarder's pubkey over the normal relay (they're already E2E via the
ratchet), keyed by `room_id`.

## 4. Forwarder pipeline (the SFU graph, audio)

> **Status: built — code-complete, compiles in `fb_desktop`, not yet
> runtime-verified.** The wiring brain is `fb::media::ForwarderRouting`
> (pure, unit-tested — `ForwarderRouting.*`): it tracks the leaf set and
> yields the edge deltas (who relays to whom) on each join/leave. The
> GStreamer muscle is `client-desktop/src/room_forwarder.{hpp,cpp}`
> (`RoomForwarder`): a `webrtcbin` per leaf, `rtpjitterbuffer → rtpopusdepay
> → tee` per source (no decoder), a `queue → rtpopuspay → subscriber.webrtc`
> branch per edge, offer/answer/ICE + renegotiation, and a `trackBinding`
> signal feeding `RoomOffer.track_bindings` (§6A.3). **Remaining:** chat_client
> wiring (instantiate it when `elect_forwarder` picks us; route
> `RoomOffer`/`RoomAnswer`/`RoomIce` to it; switch the dial plan to
> `plan_topology`), the §5 transceiver-pool optimisation (it currently
> renegotiates once per membership change), and live multi-machine
> verification (§8).

One `webrtcbin` per leaf connection. When leaf **P**'s webrtcbin exposes
P's inbound audio src pad (`on_fwd_pad_added`), bridge it to every
*other* leaf's webrtcbin **without decoding**:

```
P_webrtc.  (recv src, OPUS RTP)
   → rtpjitterbuffer            # absorb network jitter (no decode)
   → rtpopusdepay               # → SFrame-sealed Opus frame buffers
   → tee name=P_tee
P_tee. → queue → rtpopuspay pt=96 → S1_webrtc.  (sendonly transceiver)
P_tee. → queue → rtpopuspay pt=96 → S2_webrtc.
   ...                                            (one branch per S ≠ P)
```

- **No `opusdec` anywhere** → the sealed payload is relayed verbatim →
  forwarder stays blind. This is the whole point; assert it in review.
- `rtpopusdepay → rtpopuspay` strips and re-applies RTP framing only; the
  Opus payload bytes (SFrame ciphertext) are untouched.
- Dynamic: on join, add `P_webrtc` + a branch from every existing
  `*_tee` to P, and a `P_tee` branch to every existing leaf. On leave,
  release P's tee + remove P's branch from each subscriber, then EOS/unlink
  cleanly (use pad-block + `gst_pad_unlink` + element state→NULL).
- RTCP: forward NACK upstream so a publisher can FEC/retransmit; do **not**
  generate PLI (audio). Opus `inband-fec` (already on, Lever A) covers
  most loss without the forwarder doing anything.

## 5. The hard part — transceivers & renegotiation

Each leaf's PeerConnection carries 1 send (its mic) + (N−1) recv (the
others). When a new leaf joins, **every** existing leaf gains one more
recv track → SDP renegotiation on each. Plan:

- Use `webrtcbin` `on-negotiation-needed` + `create-offer` → send a fresh
  `RoomOffer`/`RoomAnswer` to that leaf; bundle all media (`bundle-policy=
  max-bundle`) so it's one transport.
- To bound renegotiations, **pre-allocate** a fixed pool of recvonly
  transceivers per leaf (e.g. up to `max_active` from Lever C) and just
  re-target which publisher feeds each — so joins past the warm pool
  don't renegotiate. This pairs naturally with active-speaker selection:
  only the top-K publishers occupy a slot.
- This transceiver/renegotiation management is the bulk of the work and
  the part raw `webrtcbin` makes manual (a libwebrtc/mediasoup SFU hides
  it). Budget accordingly.

## 6. Leaf pipeline

- **Publish:** the existing send branch — `pulsesrc → audioconvert →
  volume(mute_volume) → opusenc audio-type=voice dtx … → rtpopuspay →
  webrtcbin` — with the `sframe_seal_probe` now keyed by `K_self` (§2).
- **Subscribe:** for each inbound src pad from the forwarder, the existing
  `on_incoming_pad` audio chain — `rtpopusdepay → [sframe_open_probe keyed
  by K_sender] → opusdec → level → play_volume → autoaudiosink` — plus the
  Lever-A `level`/`play_volume` active-speaker gating already shipped.
  The sender identity per pad comes from a track→pubkey map carried in the
  `RoomOffer`. **The per-sender open-key plumbing this requires is the one
  piece §2 deferred; it is fully specified in §6A.**

## 6A. Per-sender open-key probe plumbing (detailed recv-side spec)

This is the last keying piece §2/§6 left open. Today's `sframe_open_probe`
opens *every* inbound buffer with a single `SframeProbeCtx::base_key`
(`media_call.cpp`). That is correct for 1:1 — both ends share one per-call
key — but a forwarded room fans **many** senders into one receiver, each
sealed with a *different* `K_sender = derive_room_sframe_key(room_secret,
sender_pubkey, epoch)`. So the open probe must pick the key **per inbound
stream** and survive **epoch rotation** mid-call. Three sub-problems:
(6A.2) a key registry, (6A.3) binding each pad to its sender, (6A.4)
splitting the probe + seal ctx.

### 6A.1 Shipped vs changing
- **Shipped & unchanged:** `fb::media::sframe_seal_v1/open_v1`, the wire
  format `[u32 BE epoch][u64 BE ctr][AES-256-GCM]`, `derive_room_sframe_key`
  (unit-tested incl. cross-sender isolation — `SFrameRoomKey.*`), and the
  `room_secrets` map in `chat_client` (MLS-exporter *or* distributed-RoomKey
  sourced, epoch-tagged — both shipped).
- **Shipped (the pure half of this section — §6A.9 steps 1–2):**
  `fb::media::sframe_peek_epoch`, the room-scoped **`RoomKeyRegistry`** (owns
  the secret + a derived-key cache + the epoch grace window;
  `core/{include,src}/fb/media/room_keys.*`), and the
  `RoomOffer.track_bindings` proto field with `fb::media::bind_track` /
  `sender_for_track` — all unit-tested.
- **Still to change (with the pipeline — §6A.9 steps 3–4):** `SframeProbeCtx`
  (one `base_key` for seal *and* open) splits into a single **seal ctx**
  (`K_self`, from `RoomKeyRegistry::seal_key`) + **per-pad open ctxs** (one
  per sender, calling `RoomKeyRegistry::open_key`); `set_sframe_context`
  gains a room mode; `on_incoming_pad` builds an open ctx from a pad→sender
  binding (`sender_for_track`).

### 6A.2 RoomKeyRegistry (shared, room-scoped)
One per active group call, owned by `RoomLeafCall`. Pad probes run on
GStreamer streaming threads → mutex-guarded; each key is one HKDF, cached.

```cpp
class RoomKeyRegistry {
public:
  // Called by ChatClient whenever room_secrets[room_id] changes (MLS commit
  // / RoomKey rotation). Shifts current→previous for a grace window so
  // in-flight frames at the old epoch still open.
  void set_secret(std::array<std::uint8_t,32> secret, std::uint32_t epoch);

  struct SealKey { std::array<std::uint8_t,32> key; std::uint32_t epoch; };
  // K_self at the current epoch (= derive_room_sframe_key(secret, my_pub,
  // epoch)). Seal probe reads key+epoch together.
  SealKey seal_key() const;

  // Open key for a sender at the epoch carried IN THE FRAME. Derives+caches
  // on first use. Honors the grace window: accepts current and (briefly
  // after a rotation) previous epoch; otherwise nullopt.
  std::optional<std::array<std::uint8_t,32>>
      open_key(std::string_view sender_pubkey, std::uint32_t frame_epoch);

private:
  mutable std::mutex mu_;
  std::array<std::uint8_t,32> my_pubkey_{};
  std::array<std::uint8_t,32> cur_secret_{}, prev_secret_{};
  std::uint32_t cur_epoch_=0, prev_epoch_=0;
  std::chrono::steady_clock::time_point prev_until_{};       // grace deadline
  std::map<std::pair<std::string,std::uint32_t>,
           std::array<std::uint8_t,32>> cache_;               // (sender,epoch)→K
};
```

`open_key`: select the secret whose epoch == `frame_epoch` (cur, or prev if
`now < prev_until_`); else nullopt. Then `derive_room_sframe_key(secret,
sender_pubkey, frame_epoch)`, cache by `(sender,epoch)`, return. Evict
epochs older than `prev_epoch_`; cap cache size.

### 6A.3 Binding each inbound pad to its sender
The open probe needs the pad's sender pubkey. The forwarder knows it (each
forwarded track originates from one leaf whose identity it has from the
roster), and **labeling identity is metadata, not key material — the
forwarder stays blind to content.**

**Recommended:** carry it explicitly on the (reserved) `RoomOffer`:
```proto
message TrackBinding { string mid = 1; bytes sender_pubkey = 2; }
// RoomOffer: repeated TrackBinding track_bindings = N;
```
The forwarder sets one binding per outbound media section (`mid` →
originating leaf pubkey). The subscriber, in `on_incoming_pad`, reads the
pad's transceiver `mid`, looks up `track_bindings[mid] → sender_pubkey`,
and builds the open ctx. Pure mid→pubkey map: **testable with no media.**

*Alternative (no proto change):* encode the pubkey hex in the track's SDP
`a=msid:<stream> <track>` and parse it from the pad's `mid`/caps. Workable
but stringly-typed and fragile — prefer the proto field.

### 6A.4 The reworked probes
Split the single ctx:
```cpp
struct SframeSealCtx {                 // one per call (send branch)
  RoomKeyRegistry*           reg;
  std::atomic<std::uint64_t> send_counter{0};
};
struct SframeOpenCtx {                 // one PER inbound pad (per sender)
  RoomKeyRegistry* reg;
  std::string      sender_pubkey;      // 32 bytes, from §6A.3
};
```
- **seal probe:** `auto sk = reg->seal_key(); auto c = send_counter++;
  sframe_seal_v1(sk.key, sk.epoch, c, payload)`. On rotation `seal_key()`
  returns the new key+epoch; the counter may restart at 0 because the AEAD
  nonce is `(epoch‖counter)` — a fresh epoch makes the pair unique again.
- **open probe:** read `frame_epoch` (BE u32, first 4 bytes) **before**
  opening; `auto k = reg->open_key(sender_pubkey, frame_epoch); if(!k)
  return GST_PAD_PROBE_DROP; sframe_open_v1(*k, frame)`. Add a small
  `fb::media::sframe_peek_epoch(frame)` helper (4-byte BE read) so the probe
  selects the key without duplicating the parse; `sframe_open_v1(key, frame)`
  stays unchanged (it still parses epoch+counter internally to open).

`install_sframe_recv_probe` changes from one shared ctx to **one
`SframeOpenCtx` per depayloader src pad**, allocated when the pad appears in
`on_incoming_pad` and freed on `pad-removed`/unlink (own it in the per-pad
bookkeeping struct so its lifetime tracks the pad).

### 6A.5 Seal side & `set_sframe_context` room mode
Add a room variant of `set_sframe_context`: instead of HKDF over
`(shared_secret, call_id)` into one `base_key`, point the seal ctx at the
`RoomKeyRegistry` (`seal_key()` = `derive_room_sframe_key(room_secret,
my_pubkey, epoch)`). The existing 1:1 per-call path is untouched.

### 6A.6 Epoch-rotation timeline
1. Membership change → `RoomRoster.sframe_epoch` bumps (server) and/or an
   MLS commit bumps `MlsGroup::epoch()`.
2. `chat_client` updates `room_secrets[room_id]` (already wired) **and**
   calls `registry.set_secret(secret, new_epoch)` → current shifts to
   previous; `prev_until_ = now + grace` (≈3 s).
3. Senders seal at `new_epoch` immediately; receivers open new-epoch frames
   with the new key and still open trailing old-epoch frames during grace
   (the frame header disambiguates).
4. After grace, old keys evict; any late old-epoch frame drops.

### 6A.7 Failure semantics
- **No secret yet** (call started before the MLS exporter is ready / the
  RoomKey DM arrives): `open_key` → nullopt → DROP. Brief; resumes on
  `set_secret`.
- **Forged / wrong frame / epoch past grace:** `open_key` nullopt or
  `sframe_open_v1` auth-fail → DROP (current behavior, preserved).
- **Seal failure:** fail-open (DTLS-SRTP still protects the hop) — as 1:1.
- **Non-goal:** SFrame-level replay suppression (DTLS-SRTP + AEAD integrity
  stand; per-call replay is future work).

### 6A.8 Test plan (extends §8)
- **Pure/unit (CI, no hardware) — [shipped]:** `RoomKeyRegistry` tests
  (`RoomKeyRegistry.*`) — `seal_key` rotates on `set_secret`; `open_key`
  derives the right per-sender key, isolates senders (different sender ⇒
  different key), honors the grace window (prev epoch opens within it, drops
  after — driven by an injected clock), caches, and rejects unknown/expired
  epochs; stale/duplicate `set_secret` epochs are ignored; two registries
  agree (cross-member). `sframe_peek_epoch` round-trips the sealed epoch and
  rejects short frames (`SFramePeekEpoch.*`). `TrackBindings.*` covers
  bind/lookup, missing/empty mid, and first-match. All sit next to
  `SFrameRoomKey.*`.
- **Loopback (CI-able, finicky):** two `audiotestsrc` publishers with
  distinct identities → forwarder → one subscriber holding two
  `SframeOpenCtx`. Assert it opens *both* streams (right key per pad) and
  that a deliberately swapped binding fails to open (pipeline-level
  cross-sender isolation, mirroring the unit-level guarantee).
- **Hardware:** mid-call join/leave → assert audio continuity across the
  rotation grace window.

### 6A.9 Build-order delta (refines §9 item 1)
1. **[done]** `fb::media::sframe_peek_epoch` + `RoomKeyRegistry`
   (`core/{include,src}/fb/media/room_keys.*`) + unit tests — pure, no
   hardware.
2. **[done]** `RoomOffer.track_bindings` proto field + `fb::media::bind_track`
   / `sender_for_track` (`track_bindings.*`) + unit tests — pure/testable
   ahead of media.
3. **[code-complete — compiles in `fb_desktop`]** Probe split
   (`SframeSealCtx` / per-pad heap `SframeOpenCtx`, freed via GDestroyNotify)
   in `media_call.cpp`: the seal probe pulls K_self from `seal_key()`; the
   open probe reads the frame epoch (`sframe_peek_epoch`) and opens with the
   per-sender key from `open_key()`; `on_pad_added` resolves each inbound
   track's sender from its transceiver `mid` → `_room_sender_for_mid`
   (chat_client builds that map from `RoomOffer.track_bindings`).
   `MediaCall::set_room_context(reg, mid→sender)` switches a call into room
   mode. The 1:1 / mesh path is preserved unchanged.
4. **[code-complete — compiles]** Rotation wiring: `chat_client` owns one
   `RoomKeyRegistry` per room and calls `set_secret(secret, epoch)` on every
   `room_secrets` update (MLS exporter *and* distributed RoomKey paths), so a
   room-mode call re-keys automatically.

   *Activation gap (honest):* `set_room_context` has no caller yet because
   the node that creates a room-mode call — the **§4 forwarder graph** (a
   leaf dialing the forwarder and receiving a `RoomOffer` with
   `track_bindings`) — is the remaining hardware-gated SFU build. Until it
   (or a deliberate opt-in re-key of the existing mesh path) lands, the
   room-mode branches compile but aren't entered at runtime. Live
   verification (a multi-party forwarded call) needs the loopback/hardware
   tests in §6A.8 + §8.

## 7. NAT / ICE / capacity

- The forwarder is a hub: it must be reachable by every leaf. Reuse the
  existing `FB_TURN_*` config for the relay legs; a volunteer relay peer
  should have a reachable address (or TURN).
- Capacity gate (ties to election): audio fan-out is ~`N·(N−1)·24 kbps`
  on the forwarder ≈ 17 Mbps at N=24 — fine for a fibre/volunteer peer,
  marginal for home. Keep `uplink_class` honest; fall back to mesh when
  the elected node can't sustain it (future: a measured probe, §checklist).

## 8. Test plan

- **CI-able (no hardware):** a 3-process loopback on one box —
  `audiotestsrc` publishers + a forwarder + 2 subscribers over `webrtcbin`
  on `127.0.0.1` (host ICE only). Assert: (a) each subscriber receives the
  *other* publisher's RTP, (b) the forwarder pipeline contains **zero**
  `opusdec` elements and was never handed a key (blindness), (c) an
  `appsink` byte-compare proves the sealed payload is relayed unchanged.
  webrtcbin-on-localhost ICE is finicky — budget flake-hardening.
- **Hardware:** real 3–6 node call, then scale toward ~24 audio; measure
  forwarder uplink + CPU; verify mid-call join/leave renegotiation and
  epoch rekey.
- Extend `tools/e2e/call_signal_roundtrip.sh` for the signalling
  (election → RoomOffer/Answer to forwarder) independently of media.

## 9. Build order

1. **Group keying (§2)** — per-room secret + per-sender derivation +
   epoch rotation. **[done — derivation + sourcing]**
   `fb::media::derive_room_sframe_key` ships with unit tests
   (`SFrameRoomKey.*`): determinism, per-sender / per-epoch / per-secret
   separation, and — proving it's a real SFrame base key —
   seal-with-A's-key/open-with-A's-key plus cross-sender isolation (A's
   frame won't open with B's key). The `room_secret` is now **sourced** for
   both channel types: MLS via `MlsGroup::export_room_secret()`
   (`state.do_export`, unit-tested for cross-member agreement + rotation),
   SenderKeys via the distributed `RoomKey` DM (`roomkey_roundtrip.sh`); both
   land in `chat_client`'s unified `room_secrets` map. *Remaining:* feed the
   per-sender keys into the media probes — **fully specified in §6A**
   (`RoomKeyRegistry`, `sframe_peek_epoch`, the seal/open ctx split, pad→
   sender binding, epoch grace) — lands with the pipeline build below; the
   pure pieces (§6A.9 steps 1–2) can land ahead of it.
2. **Forwarder graph (§4)** — **[built, code-complete; compiles, not
   runtime-verified]** `fb::media::ForwarderRouting` (pure, unit-tested) +
   `RoomForwarder` (the webrtcbin-per-leaf + tee + per-edge repay graph, no
   decoder). Proving blind relay for 3 nodes is the loopback test (§8), still
   to run on hardware.
3. **Dynamic join/leave + renegotiation (§5)** — `RoomForwarder` does the
   simple "one renegotiation per membership change" form today; the
   pre-allocated transceiver pool is the remaining optimisation.
4. **Switch the dial plan** to `plan_topology` (leaf → forwarder only)
   behind a flag; keep mesh as fallback. Includes the chat_client wiring that
   instantiates `RoomForwarder` on the elected node and routes
   `RoomOffer`/`RoomAnswer`/`RoomIce` to it.
5. **Active-speaker forwarding (Lever C)** — only relay top-K publishers;
   reuse the shipped `select_active_speakers` + `plan_forwarded_video`.

## 10. Reuse map (don't rebuild)
- SFrame seal/open: `sframe_seal_probe` / `sframe_open_probe`,
  `fb::media::sframe` wire format — unchanged.
- Inbound pad handling: `on_incoming_pad` in `media_call.cpp` — extend,
  don't fork.
- Election/plan: `fb::media::elect_forwarder` / `plan_topology` — shipped.
- Active-speaker gate: `fb::media::select_active_speakers`,
  `MediaCall::set_playback_muted`, the `level` element — shipped.
- Signalling transport: `DmPayload.media_signal` + `RoomOffer/Answer/Ice`.
