#!/usr/bin/env bash
# End-to-end test: spin up fb_server + two fb-cli peers, send a
# Frame.peer (PeerEnvelope) from alice → bob via the central relay,
# and assert (a) bob receives the marker payload, (b) the server log
# never contains the marker plaintext (server only forwards the
# opaque payload bytes; it doesn't log them).
#
# Validates the N1 plumbing: kPeer dispatch on the server side +
# PeerEnvelope addressing by recipient_pubkey. This is the wire path
# DhtNode + UsernameGossip use for production peer-to-peer overlay
# traffic.
#
# Usage: tools/e2e/peer_envelope_relay.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBE2E-OVERLAY-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built" >&2; exit 1; }
[[ -x "${CLI_BIN}" ]]    || { echo "FAIL: fb-cli not built" >&2; exit 1; }

PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
PY
)

SCRATCH="$(mktemp -d -t fbe2e_overlay.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
BOB_OUT="${SCRATCH}/bob.stdout"
BOB_ERR="${SCRATCH}/bob.stderr"
ALICE_OUT="${SCRATCH}/alice.stdout"
ALICE_ERR="${SCRATCH}/alice.stderr"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

echo "== launching fb_server on 127.0.0.1:${PORT}"
"${SERVER_BIN}" --host 127.0.0.1 --port "${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    if (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then break; fi
    sleep 0.05
done

echo "== launching fb-cli overlay-recv as bob"
"${CLI_BIN}" --user bob --overlay-recv --wait-ms 5000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.4   # let bob register so alice's UsernameLookup finds him

echo "== launching fb-cli overlay-send as alice (payload: ${MARKER})"
"${CLI_BIN}" --user alice --overlay-send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${PORT}" >"${ALICE_OUT}" 2>"${ALICE_ERR}"

wait "${BOB_PID}" || true

echo "== inspecting bob output"
if ! grep -Fq "OVERLAY-RECV" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive overlay envelope" >&2
    echo "----- bob.stdout -----" >&2; cat "${BOB_OUT}" >&2
    echo "----- bob.stderr -----" >&2; cat "${BOB_ERR}" >&2
    echo "----- alice.stdout ---" >&2; cat "${ALICE_OUT}" >&2
    echo "----- alice.stderr ---" >&2; cat "${ALICE_ERR}" >&2
    echo "----- server.log -----" >&2; cat "${SERVER_LOG}" >&2
    exit 1
fi
if ! grep -Fq "${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob received an envelope but payload didn't match marker" >&2
    cat "${BOB_OUT}" >&2
    exit 1
fi

echo "== confirming server-blindness (marker must not appear in server log)"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained payload — server is NOT blind to PeerEnvelope contents!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: peer-envelope round-trip via central relay + payload-blindness."
echo "  marker:        ${MARKER}"
echo "  port:          ${PORT}"
echo "  bob received:  $(grep 'OVERLAY-RECV' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no payload)"
