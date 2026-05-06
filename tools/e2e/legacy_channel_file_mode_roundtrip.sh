#!/usr/bin/env bash
# LEGACY — file-mode channel test. Kept for diagnostic coverage of the
# fb-cli --channel-create / --channel-listen flags but NOT the canonical
# channel test (channel_inband_roundtrip.sh is the in-band flow the
# desktop UI now uses).
#
# spin up the FinBit server + 3 fb-cli peers in a channel,
# alice creates the chain + sends, bob and carol both decrypt. Asserts
# server-blindness against the random channel marker.
#
# Usage: tools/e2e/legacy_channel_file_mode_roundtrip.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBCH-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}" ]]    || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }

PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)

SCRATCH="$(mktemp -d -t fbch.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
ALICE_OUT="${SCRATCH}/alice.stdout"
BOB_OUT="${SCRATCH}/bob.stdout"
CAROL_OUT="${SCRATCH}/carol.stdout"
DIST="${SCRATCH}/alice.dist"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    [[ -n "${CAROL_PID:-}"  ]] && kill "${CAROL_PID}"  2>/dev/null || true
    [[ -n "${ALICE_PID:-}"  ]] && kill "${ALICE_PID}"  2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

CHAN_NAME="testchan-${MARKER}"

echo "== launching fb_server on 127.0.0.1:${PORT}"
"${SERVER_BIN}" --host 127.0.0.1 --port "${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    if (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then break; fi
    sleep 0.05
done

echo "== launching alice (channel-create + send + linger)"
"${CLI_BIN}" --user alice --channel-create --channel-name "${CHAN_NAME}" \
    --dist-file "${DIST}" --text "${MARKER}" --linger-ms 1500 \
    --server "127.0.0.1:${PORT}" >"${ALICE_OUT}" 2>&1 &
ALICE_PID=$!

echo "== waiting for alice's distribution"
for _ in {1..40}; do
    [[ -s "${DIST}" ]] && break
    sleep 0.1
done
[[ -s "${DIST}" ]] || { echo "FAIL: distribution file never appeared" >&2; exit 1; }

echo "== launching bob + carol (channel-listen)"
"${CLI_BIN}" --user bob --channel-listen --channel-name "${CHAN_NAME}" \
    --dist-file "${DIST}" --wait-ms 4000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>&1 &
BOB_PID=$!
"${CLI_BIN}" --user carol --channel-listen --channel-name "${CHAN_NAME}" \
    --dist-file "${DIST}" --wait-ms 4000 \
    --server "127.0.0.1:${PORT}" >"${CAROL_OUT}" 2>&1 &
CAROL_PID=$!

wait "${ALICE_PID}" || true
wait "${BOB_PID}"   || true
wait "${CAROL_PID}" || true

echo "== checking bob received the channel msg"
if ! grep -Fq "CHAN-MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not see CHAN-MSG. bob.stdout:" >&2
    cat "${BOB_OUT}" >&2
    echo "----- server.log -----" >&2; cat "${SERVER_LOG}" >&2
    exit 1
fi
echo "== checking carol received the channel msg"
if ! grep -Fq "CHAN-MSG: ${MARKER}" "${CAROL_OUT}"; then
    echo "FAIL: carol did not see CHAN-MSG. carol.stdout:" >&2
    cat "${CAROL_OUT}" >&2
    echo "----- server.log -----" >&2; cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "== confirming server-blindness on the channel path"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained channel plaintext marker!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: end-to-end channel fanout to 2 receivers + server-blindness."
echo "  marker:        ${MARKER}"
echo "  bob received:  $(grep -F 'CHAN-MSG:' "${BOB_OUT}")"
echo "  carol received: $(grep -F 'CHAN-MSG:' "${CAROL_OUT}")"
echo "  server log size: $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
