#!/usr/bin/env bash
# Username-on-receive test:
#   1. bob registers + listens
#   2. alice DMs bob with a marker
#   3. bob receives the marker AND issues a UsernameLookup for alice's pubkey
#   4. server (knowing alice's pubkey from her ClientHello + IdentityClaim)
#      returns "alice"
#   5. bob's listener prints "USER: alice"
# Asserts both the message marker and the USER: alice line appear in bob's
# stdout, and that the marker never appears in the server log.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBUSER-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"
SERVER="${BUILD}/server/fb_server"
CLI="${BUILD}/tools/fb-cli/fb-cli"

PORT=$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)
SCRATCH="$(mktemp -d -t fbuser.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
BOB_OUT="${SCRATCH}/bob.out"
BOB_LOG="${SCRATCH}/bob.log"
ALICE_LOG="${SCRATCH}/alice.log"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

"${SERVER}" --host 127.0.0.1 --port "${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null && break; sleep 0.05; done

"${CLI}" --user bob --listen --wait-ms 4000 --server "127.0.0.1:${PORT}" \
    >"${BOB_OUT}" 2>"${BOB_LOG}" &
BOB_PID=$!
sleep 0.3

"${CLI}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${PORT}" 2>"${ALICE_LOG}"

wait "${BOB_PID}" || true
BOB_PID=""

if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the marker" >&2
    cat "${BOB_OUT}" >&2 ; cat "${BOB_LOG}" >&2 ; cat "${SERVER_LOG}" >&2
    exit 1
fi
if ! grep -Fq "USER: alice" "${BOB_OUT}"; then
    echo "FAIL: bob did not resolve alice's username" >&2
    cat "${BOB_OUT}" >&2
    exit 1
fi
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained the plaintext marker" >&2
    exit 1
fi

echo "PASS: username-on-receive resolves the sender alongside the message."
echo "  marker:        ${MARKER}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  bob resolved:  $(grep -F 'USER:' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
