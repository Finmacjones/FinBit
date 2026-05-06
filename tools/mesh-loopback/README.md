# mesh-loopback

A simulated MeshCore companion node for development without LoRa hardware.

## Plan (Phase 4)

Two scripts, both shipped here:

1. `pty-pair.sh` — uses `socat -d -d pty,raw,echo=0 pty,raw,echo=0` to
   create a virtual serial pair. The fb-cli serial bridge opens one end
   (e.g. `/dev/pts/13`), this loopback opens the other.

2. `loopback.py` — speaks the Meshtastic protobuf-over-serial protocol on
   one end of the pair. Reads outbound frames from FinBit and either echoes
   them straight back (smoke test) or routes between several simulated nodes
   to exercise multi-hop / SNR / hop-limit metadata paths.

## Hardware-in-loop alternative

When a real Heltec/RAK MeshCore board is wired in, the bridge code is the
same — it just opens `/dev/ttyUSB0` directly. CI should retain at least one
runner with a live device on a low-power test channel; the loopback alone
will not catch radio-layer surprises.

PHASE 0 STATUS: README only. Scripts to be added when the serial bridge
implementation lands in Phase 4.
