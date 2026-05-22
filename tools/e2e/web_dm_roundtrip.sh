#!/usr/bin/env bash
# Web-client end-to-end test: a Node.js script using the FinBit WASM
# module + the new WebSocket transport sends a DM to bob, who is
# listening on the existing TCP path via fb-cli. bob's listener prints
# the marker; the script asserts it appears and never reaches the
# server log as plaintext.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBWEB-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"
SERVER="${BUILD}/server/fb_server"
CLI="${BUILD}/tools/fb-cli/fb-cli"
# Node from $FB_NODE if set, else whatever's on PATH (emsdk ships one).
NODE="${FB_NODE:-$(command -v node || true)}"

[[ -x "${SERVER}" ]] || { echo "FAIL: server not built" >&2; exit 1; }
[[ -x "${CLI}"    ]] || { echo "FAIL: fb-cli not built" >&2; exit 1; }
[[ -n "${NODE}" && -x "${NODE}" ]] || { echo "FAIL: node not found — set FB_NODE or add node to PATH" >&2; exit 1; }
[[ -f "${REPO_ROOT}/client-web/build/finbit.mjs" ]] || {
    echo "FAIL: WASM not built — run scripts/build-wasm.sh" >&2; exit 1; }

# Two free ports: TCP for fb-cli, WS for the web client.
PORTS=$(python3 - <<'PY'
import socket
out = []
for _ in range(2):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); out.append(s.getsockname()[1]); s.close()
print(" ".join(str(p) for p in out))
PY
)
read -r TCP_PORT WS_PORT <<< "${PORTS}"

SCRATCH="$(mktemp -d -t fbweb.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
BOB_OUT="${SCRATCH}/bob.out"
BOB_LOG="${SCRATCH}/bob.log"
WEB_LOG="${SCRATCH}/web.log"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

echo "== fb_server: tcp=${TCP_PORT}, ws=${WS_PORT}"
"${SERVER}" --host 127.0.0.1 --port "${TCP_PORT}" --ws-port "${WS_PORT}" \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    (echo > /dev/tcp/127.0.0.1/${TCP_PORT}) 2>/dev/null && break
    sleep 0.05
done

echo "== bob: fb-cli --listen on TCP"
"${CLI}" --user bob --listen --wait-ms 6000 --server "127.0.0.1:${TCP_PORT}" \
    >"${BOB_OUT}" 2>"${BOB_LOG}" &
BOB_PID=$!
sleep 0.4

echo "== web (Node): connect WS, send DM to bob"
WS_URL="ws://127.0.0.1:${WS_PORT}" \
WEB_USER=alice PEER=bob MARKER="${MARKER}" \
    "${NODE}" "${REPO_ROOT}/client-web/test/web_dm_node.mjs" 2>"${WEB_LOG}"

wait "${BOB_PID}" || true
BOB_PID=""

if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the marker." >&2
    echo "--- bob.out ---" >&2; cat "${BOB_OUT}" >&2
    echo "--- bob.log ---" >&2; cat "${BOB_LOG}" >&2
    echo "--- web.log ---" >&2; cat "${WEB_LOG}" >&2
    echo "--- server.log ---" >&2; cat "${SERVER_LOG}" >&2
    exit 1
fi
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: marker leaked into server log!" >&2
    exit 1
fi

echo "PASS: web client DM via WebSocket → server (TCP-side bob received plaintext)."
echo "  marker:        ${MARKER}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
