#!/usr/bin/env bash
# End-to-end test for the GROUP-CALL lazy session bootstrap + media-call
# signaling, headless (no GStreamer / mic / camera).
#
# It exercises the exact chain the desktop's group-voice dialer uses when
# it meets a peer it has never DM'd:
#
#   peer PUBKEY  →  username_lookup  →  key_fetch  →  init_alice
#                →  media_signal OFFER  →  (peer init_bob, decrypt)
#                →  media_signal ANSWER  →  (offerer decrypt)
#
# bob runs `--call-listen` (registers, prints MY-PUBKEY, answers OFFERs);
# alice runs `--call-offer --peer-pubkey <bob>` having NEVER DM'd bob, so
# the whole session is bootstrapped from just his pubkey. The SDP is a
# marker string, so no real media is needed.
#
# Assertions:
#   - bob prints   CALL-OFFER: <marker>          (bootstrap + decrypt worked)
#   - alice prints CALL-ANSWER: ... <marker>     (reverse leg worked)
#   - the server log NEVER contains the marker   (relay is blind to SDP)
#
# Usage: tools/e2e/call_signal_roundtrip.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBCALL-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-SDP}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}" ]]    || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')

SCRATCH="$(mktemp -d -t fbe2e_call.XXXXXX)"
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

echo "== launching fb-cli --call-listen as bob"
"${CLI_BIN}" --user bob --call-listen --wait-ms 12000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!

# Wait for bob to register + advertise his pubkey (mirrors the roster
# surfacing a peer's pubkey to the dialer).
BOB_PUB=""
for _ in {1..60}; do
    # `|| true` keeps pipefail+errexit from killing us on the (expected)
    # early iterations before bob has printed the line yet.
    BOB_PUB="$(grep -m1 '^MY-PUBKEY: ' "${BOB_OUT}" 2>/dev/null | awk '{print $2}' || true)"
    [[ -n "${BOB_PUB}" ]] && break
    sleep 0.1
done
if [[ -z "${BOB_PUB}" ]]; then
    echo "FAIL: bob never printed MY-PUBKEY" >&2
    echo "----- bob.stderr -----" >&2; cat "${BOB_ERR}" >&2
    echo "----- server.log -----" >&2; cat "${SERVER_LOG}" >&2
    exit 1
fi
echo "== bob pubkey: ${BOB_PUB}"

echo "== launching fb-cli --call-offer as alice (never DM'd bob)"
"${CLI_BIN}" --user alice --call-offer --peer-pubkey "${BOB_PUB}" \
    --text "${MARKER}" --wait-ms 8000 \
    --server "127.0.0.1:${PORT}" >"${ALICE_OUT}" 2>"${ALICE_ERR}" || true

wait "${BOB_PID}" || true

dump() {
    echo "----- bob.stdout -----"   >&2; cat "${BOB_OUT}"   >&2
    echo "----- bob.stderr -----"   >&2; cat "${BOB_ERR}"   >&2
    echo "----- alice.stdout -----" >&2; cat "${ALICE_OUT}" >&2
    echo "----- alice.stderr -----" >&2; cat "${ALICE_ERR}" >&2
    echo "----- server.log -----"   >&2; cat "${SERVER_LOG}" >&2
}

echo "== asserting bob received the OFFER (bootstrap from pubkey worked)"
if ! grep -Fq "CALL-OFFER: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the OFFER marker" >&2
    dump
    exit 1
fi

echo "== asserting alice received the ANSWER (reverse leg worked)"
if ! grep -Fq "CALL-ANSWER: " "${ALICE_OUT}" || ! grep -Fq "${MARKER}" "${ALICE_OUT}"; then
    echo "FAIL: alice did not receive the ANSWER" >&2
    dump
    exit 1
fi

echo "== confirming server-blindness (SDP marker must not appear in server log)"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained the SDP marker — relay is NOT blind!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: headless call-signaling round-trip (lazy bootstrap → OFFER/ANSWER)."
echo "  marker:        ${MARKER}"
echo "  port:          ${PORT}"
echo "  bob:           $(grep -F 'CALL-OFFER:' "${BOB_OUT}")"
echo "  alice:         $(grep -F 'CALL-ANSWER:' "${ALICE_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no SDP plaintext)"
