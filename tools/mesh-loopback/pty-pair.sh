#!/usr/bin/env bash
# Create a virtual serial pair via socat for development without LoRa
# hardware. Prints the two PTY paths to stdout and stays running until
# killed.
#
# Typical use:
#   $ tools/mesh-loopback/pty-pair.sh &
#   PTY_A=/dev/pts/12   # one end - hand to fb's serial bridge
#   PTY_B=/dev/pts/13   # other end - hand to loopback.py
#
# Both ends behave like a normal serial port at 115200 8N1.

set -euo pipefail
exec socat -d -d \
    pty,raw,echo=0,b115200,wait-slave \
    pty,raw,echo=0,b115200,wait-slave
