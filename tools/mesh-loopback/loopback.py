#!/usr/bin/env python3
"""Simulated MeshCore companion node for FinBit's serial bridge.

Reads the FinBit serial wire format ([u16 BE length][N bytes payload]) from a
PTY, optionally mutates the payload, and writes it back out as a new frame —
simulating either a loopback echo or a single-hop mesh relay.

Use with tools/mesh-loopback/pty-pair.sh:

    socat -d -d pty,raw,echo=0,b115200 pty,raw,echo=0,b115200
    # note the two PTYs printed (e.g. /dev/pts/12 and /dev/pts/13)
    ./tools/mesh-loopback/loopback.py /dev/pts/13 &
    # then point fb's serial bridge at /dev/pts/12

PHASE 0/1 status: echo-only behaviour. Phase 4 will swap this for a real
Meshtastic protobuf loopback once the schema is wired in.
"""
from __future__ import annotations

import os
import struct
import sys
import termios
import time


def configure_serial(fd: int, baud: int = termios.B115200) -> None:
    attrs = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
    iflag = 0
    oflag = 0
    cflag = (cflag & ~termios.CSIZE) | termios.CS8 | termios.CLOCAL | termios.CREAD
    cflag &= ~(termios.PARENB | termios.CSTOPB)
    lflag = 0
    cc[termios.VMIN] = 0
    cc[termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, [iflag, oflag, cflag, lflag, baud, baud, cc])


def read_exact(fd: int, n: int, deadline: float) -> bytes:
    out = b""
    while len(out) < n:
        if time.monotonic() > deadline:
            return b""
        chunk = os.read(fd, n - len(out))
        if not chunk:
            time.sleep(0.01)
            continue
        out += chunk
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: loopback.py /dev/pts/N", file=sys.stderr)
        return 1
    path = argv[1]
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
    configure_serial(fd)
    print(f"loopback.py listening on {path}", file=sys.stderr)
    try:
        while True:
            hdr = read_exact(fd, 2, time.monotonic() + 60.0)
            if not hdr:
                continue
            (length,) = struct.unpack(">H", hdr)
            payload = read_exact(fd, length, time.monotonic() + 5.0)
            if not payload:
                continue
            # Echo back (with a small mutation so we can confirm the round-trip).
            mutated = b"echo:" + payload
            os.write(fd, struct.pack(">H", len(mutated)) + mutated)
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
