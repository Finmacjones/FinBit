#!/usr/bin/env python3
"""Tiny in-process MQTT 3.1.1 broker for FinBit's mesh-bridge tests.

Backed by the `amqtt` library — runs forever (or until Ctrl-C) listening
on the host:port passed via argv. Used by tools/e2e/mqtt_roundtrip.sh
when no system mosquitto is available.

amqtt is a pure-Python MQTT broker that supports the subset (CONNECT,
SUBSCRIBE, PUBLISH, QoS 0/1/2) the C++ Paho client uses. Logs go to
stderr; they should not contain any plaintext beyond the random marker
the test sends, and the test asserts that's the only place it appears.
"""
from __future__ import annotations

import asyncio
import logging
import sys

from amqtt.broker import Broker

CONFIG = {
    "listeners": {"default": {"type": "tcp", "bind": None}},
    # New-style plugins config — anonymous auth on, no topic ACL, no $SYS
    # publisher, no auth_file with a missing password file.
    "plugins": {
        "amqtt.plugins.authentication.AnonymousAuthPlugin": {
            "allow_anonymous": True
        },
    },
}


async def main() -> int:
    if len(sys.argv) < 2:
        print("usage: mqtt_broker.py HOST:PORT", file=sys.stderr)
        return 1
    bind = sys.argv[1]
    cfg = dict(CONFIG)
    cfg["listeners"] = {"default": {"type": "tcp", "bind": bind}}
    logging.basicConfig(level=logging.WARNING)
    broker = Broker(cfg)
    await broker.start()
    print(f"mqtt_broker.py listening on {bind}", file=sys.stderr)
    try:
        await asyncio.Event().wait()
    finally:
        await broker.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
