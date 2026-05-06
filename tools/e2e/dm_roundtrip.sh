#!/usr/bin/env bash
# End-to-end test: spin up the FinBit server + two fb-cli peers, exchange a
# DM, and assert (a) the recipient decrypts it and (b) the server logs never
# contained the plaintext.
#
# Usage: tools/e2e/dm_roundtrip.sh [build-dir] [secret-marker]
#   build-dir defaults to build/system
#   secret-marker defaults to a random magic string used as the message body

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBE2E-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}" ]]    || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }

# Pick a free port (let the kernel choose one we know is unused right now).
PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)

SCRATCH="$(mktemp -d -t fbe2e.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
BOB_OUT="${SCRATCH}/bob.stdout"
BOB_ERR="${SCRATCH}/bob.stderr"
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

# Wait for the listener to be up.
for _ in {1..40}; do
    if (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then break; fi
    sleep 0.05
done

echo "== launching fb-cli listen as bob"
"${CLI_BIN}" --user bob --listen --wait-ms 5000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.3   # let bob register + upload bundle

echo "== launching fb-cli send as alice"
"${CLI_BIN}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${PORT}" 2>"${ALICE_ERR}"

# Wait for bob to print + exit.
wait "${BOB_PID}" || true

echo "== inspecting bob output"
if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the marker. bob.stdout was:" >&2
    cat "${BOB_OUT}" >&2
    echo "----- bob.stderr -----" >&2
    cat "${BOB_ERR}" >&2
    echo "----- server.log -----" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "== confirming server-blindness (marker must not appear in server log)"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained plaintext marker — server is NOT blind!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: end-to-end DM round-trip + server-blindness assertion."
echo "  marker:        ${MARKER}"
echo "  port:          ${PORT}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  server log size: $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
