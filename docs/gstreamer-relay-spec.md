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
1:1 ctx must split into seal-key + per-sender open-keys — that wiring is
part of the pipeline build, §6).

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

One `webrtcbin` per leaf connection. When leaf **P**'s webrtcbin exposes
P's inbound audio src pad (extend `on_incoming_pad`), bridge it to every
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
  The sender identity per pad comes from the SDP `msid` / a track→pubkey
  map carried in the `RoomOffer`.

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
   epoch rotation. **[done — derivation]** `fb::media::derive_room_sframe_key`
   ships with unit tests (`SFrameRoomKey.*`): determinism, per-sender /
   per-epoch / per-secret separation, and — proving it's a real SFrame
   base key — seal-with-A's-key/open-with-A's-key plus cross-sender
   isolation (A's frame won't open with B's key). *Remaining:* source the
   `room_secret` (MLS `state.do_export("FinBit-room-sframe", …)` exposed
   via `mls_facade`; or a distributed `RoomKey` for SenderKeys channels),
   and feed per-sender keys into the media probes (§6) — both land with
   the pipeline build below.
2. **Forwarder graph (§4)** for a *fixed* small N (no renegotiation) —
   prove blind relay works for 3 nodes via the loopback test.
3. **Dynamic join/leave + renegotiation (§5)** — the transceiver pool.
4. **Switch the dial plan** to `plan_topology` (leaf → forwarder only)
   behind a flag; keep mesh as fallback.
5. **Active-speaker forwarding (Lever C)** — only relay top-K publishers;
   reuse the shipped `select_active_speakers`.

## 10. Reuse map (don't rebuild)
- SFrame seal/open: `sframe_seal_probe` / `sframe_open_probe`,
  `fb::media::sframe` wire format — unchanged.
- Inbound pad handling: `on_incoming_pad` in `media_call.cpp` — extend,
  don't fork.
- Election/plan: `fb::media::elect_forwarder` / `plan_topology` — shipped.
- Active-speaker gate: `fb::media::select_active_speakers`,
  `MediaCall::set_playback_muted`, the `level` element — shipped.
- Signalling transport: `DmPayload.media_signal` + `RoomOffer/Answer/Ice`.
