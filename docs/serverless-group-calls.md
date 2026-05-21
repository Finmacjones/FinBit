<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Group calls to ~24 **without a dedicated SFU**

> Goal: Discord-style group voice (and useful group video) up to ~24
> participants, keeping FinBit's serverless / E2E posture — i.e. **no
> mediasoup/Janus media server** to deploy, and no plaintext ever visible
> to any forwarder.
>
> Status: design + checklist. Today: full-mesh, ~5–6 participants, SFrame
> end-to-end frame encryption already shipped (`core/src/media/sframe.cpp`),
> lazy session bootstrap + headless call-signaling e2e shipped. The
> `RoomOffer` / `RoomAnswer` / `RoomIce` protos are reserved
> (`core/proto/envelope.proto`) for the forwarding step below.

## 1. The math you can't cheat

In a call where everyone sees/hears everyone, the room delivers
**N·(N−1)** media streams total; each participant *receives* N−1. The
only question is **who uploads them**:

| Topology | Upload per node | Who pays |
| --- | --- | --- |
| **Full mesh** | (N−1) × bitrate | every participant |
| **Single forwarder** (SFU-shaped) | sender: 1×; forwarder: up to N·(N−1)× | one node |
| **Cascade / tree** | fan-out F × layers carried | spread across peers |

So "no SFU" can't mean "nobody forwards" — for your stream to reach N
people having sent it **once**, *something* forwards it. The real choice
is **where the forwarder runs**: a dedicated media server (classic SFU)
vs. **a participant or a volunteer peer** (what FinBit does). Mixing
audio on a forwarder (MCU style) is off the table — it requires
*decrypting*, which breaks E2E; **forwarding** SFrame ciphertext does not.

Concrete bitrates (Opus voice ≈ 32 kbps, VP8/AV1 video ≈ 300–800 kbps):

- **Audio, 24-way mesh:** 23 × ~32 kbps ≈ **0.7 Mbps up** per node — fine
  on ordinary broadband. The limiter is CPU (23 decoders) and 23 NAT
  traversals, both addressable (below).
- **Video, 24-way mesh:** 23 × ~500 kbps ≈ **11.5 Mbps up** per node —
  not realistic for home uplinks.
- **Video, single peer-forwarder, 24-way:** ≈ **276 Mbps** aggregate on
  the forwarder — that's a datacenter, not a peer.

⇒ **Audio to 24 is achievable with no forwarder at all.** Group **video**
to 24 needs forwarding *and* selectivity (you never actually need 24
full-res videos at once) *and* load-spreading. None of that requires a
dedicated SFU product — it requires the participants (and optionally the
relay you already run) to forward.

## 2. The design — four levers, each independently shippable

### Lever A — Optimized full-mesh audio (no forwarder)  → ~15–20
- **Opus DTX** (discontinuous transmission): silent participants send
  ~0. In a 24-person room with 1–2 talkers, real audio bandwidth is a
  fraction of the worst case.
- **Active-speaker selection:** each client only *decodes/plays* the top
  ~4 RMS-loudest streams; the rest are received-but-muted (or not
  subscribed). Caps CPU regardless of N.
- Pure pipeline + signalling work on the existing mesh; no new transport.

### Lever B — Peer-forwarder ("relay peer")  → audio to ~24, small-room video
- The room **elects** the best-connected participant (highest measured
  uplink / most stable) — or a **volunteer relay peer** (fits FinBit's
  existing PeerNet/relay model) — to forward.
- Each participant sends their stream **once** to the forwarder; the
  forwarder fans it out. **SFrame keeps the forwarder blind** — it
  forwards ciphertext frames it can't read.
- This is the SFU's *function* on a peer, not a deployed SFU *service*.
  Wire it through the reserved `RoomOffer`/`RoomAnswer`/`RoomIce` frames
  (participant ↔ forwarder), reusing the `DmPayload.media_signal` SDP/ICE
  machinery already in place for 1:1.
- Audio to ~24 is comfortable here (~17 Mbps aggregate on a good home
  uplink); full-res video stays limited to small rooms — hence Lever C.

### Lever C — Selective + simulcast video  → 24-way video, realistic bandwidth
- **Simulcast / SVC:** each sender publishes a low layer (~80 kbps
  thumbnail) and a high layer (~500 kbps).
- The forwarder relays the **high** layer only for the few **on-screen /
  active** participants and the **low** thumbnail (or nothing) for the
  rest. A 24-grid that shows 24 full-res videos simultaneously isn't a
  real product requirement — Discord shows a handful active + thumbnails.
- Cuts forwarder egress by an order of magnitude (e.g. 5 active×high +
  19×thumb ≈ tens of Mbps, not 276).

### Lever D — Cascade / tree forwarding  → no single node carries O(N²)
- Spread forwarding across **several** peers in a shallow fan-out tree
  (depth ≤ 2 to keep conversational latency; each hop ~20–60 ms).
- Each peer forwards to F others (F≈3–4), so aggregate uplink per node
  stays bounded as N grows. This is a **distributed SFU built from the
  participants** — the serverless end-state.
- SFrame still applies: every interior node forwards ciphertext.

### FinBit-specific leverage (why this is a fit, not a rewrite)
- **SFrame already shipped** → any forwarder (peer, tree node, or relay)
  is E2E-blind by construction.
- **PeerNet + DHT + gossip already exist** → the forwarding overlay,
  forwarder election, and presence are extensions of shipped machinery,
  not new infrastructure.
- **The existing relay is already E2E-blind** (SFrame) → a self-hoster
  who *wants* server-assisted scaling can let **the relay they already
  run** forward media, instead of standing up a separate mediasoup/Janus.
  That's an operator option, not a required dependency.
- **Reserved protos** (`RoomOffer/RoomAnswer/RoomIce`) were added for
  exactly this signalling.

## 3. Honest limits
- **24 full-res videos at once** is not a goal and not feasible without a
  datacenter; "24-way video" means active-speaker high-res + thumbnails.
- **Cascade adds latency** per hop — fine for ≤2 hops, audible past that;
  keep trees shallow, prefer a single strong forwarder for small rooms.
- **Forwarder uplink is the real cap.** A room of 24 on home uplinks
  needs Lever C+D; a room with one fibre/relay peer can lean on Lever B.
- This is **more engineering than dropping in mediasoup** — but it keeps
  the serverless + E2E properties that are the whole point of FinBit.

## 4. Checklist

### Group calls without an SFU
- [x] Full-mesh 1:1 + small-room voice/video (≤~6) — `media_call.cpp`
- [x] SFrame E2E frame encryption (forwarders stay blind) — `sframe.cpp`
- [x] Lazy group-call session bootstrap (dial a never-DM'd roster peer)
- [x] Headless call-signalling e2e (`tools/e2e/call_signal_roundtrip.sh`)
- [x] **Lever A:** Opus DTX (+ voice-mode, constrained-VBR, inband-FEC) in
      the send pipeline — `media_call.cpp`
- [x] **Lever A:** active-speaker selection — per-peer RMS metering
      (`level` element → `MediaCall::audioLevel`) + top-K selector
      (`fb::media::select_active_speakers`, unit-tested) gating playback
      via `play_volume`
- [x] **Lever A:** no hard participant cap in code; audio now scales to
      ~15–20 on the mesh (docs updated). *Note:* real-device load-test
      and a pre-decoder frame-drop (deeper CPU cap) remain — done on a
      box with audio hardware.
- [x] **Lever B:** deterministic forwarder *election* + topology plan —
      pure, unit-tested (`fb::media::elect_forwarder` / `plan_topology`),
      driven by a `uplink_class` hint on `RoomJoin`/`RoomMember` (threaded
      through the server roster + gossip beacon); computed + logged on every
      roster change in `chat_client` (mesh dial plan untouched until the
      relay pipeline lands).
- [x] **Lever B:** volunteer "relay peer" mode — `FB_FORWARDER_VOLUNTEER=1`
      (class 3) / `FB_FORWARDER_CLASS=0..3`.
- [ ] **Lever B:** GStreamer peer media-relay pipeline — terminate N
      PeerConnections, re-pay SFrame-sealed RTP to subscribers WITHOUT
      decoding (forwarder stays blind). *Real-hardware / multi-machine
      build — the election + plan above are the hook it consumes.*
      **Full implementation spec: `docs/gstreamer-relay-spec.md`** (group
      SFrame keying, the SFU element graph, renegotiation, test plan).
- [ ] **Lever B:** wire `RoomOffer`/`RoomAnswer`/`RoomIce` for the
      participant ↔ forwarder media handshake (depends on the relay
      pipeline)
- [ ] **Lever B:** switch the dial plan to `plan_topology` (leaf → dial
      only the forwarder) once the relay pipeline can carry it
- [ ] **Lever B:** measured uplink probe (today `uplink_class` is a
      declared hint, not a measurement)
- [ ] **Lever C:** simulcast/SVC layers in the encoder (low thumb + high)
- [ ] **Lever C:** selective forwarding (active high-res + thumbnails)
- [ ] **Lever D:** fan-out cascade tree (depth ≤2) + per-hop latency budget
- [ ] **Optional:** relay-assisted media forwarding for self-hosters
- [ ] Headless multi-party forwarding e2e (extend the call-signal harness)

### Large media / file transfer (the other "needs forwarding" item)
- [x] Inline images/GIFs ≤256 KB (DM + channel, persisted, E2E)
- [ ] Chunked, content-addressed blob transfer for large files/media
- [ ] Per-chunk AEAD + resumable upload/download
- [ ] P2P blob transfer over PeerNet when both peers online; relay-store
      fallback when offline (reuse the offline-relay model)
- [ ] Raise/relax the 256 KB inline cap once the blob path exists

### Screen-share
- [ ] Per-OS capture source (PipeWire / DXGI / ScreenCaptureKit) → encoder
- [ ] Share-screen UI + permission flow; rides the same forwarding levers

See also: `docs/ROADMAP.md` (broader deferred list),
`docs/censorship-resistance.md` (transport tiers).
