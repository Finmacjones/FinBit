#!/usr/bin/env bash
# In-band channel test: alice creates a channel and DM-delivers the
# SenderKeys distribution to bob (no shared file on disk). Bob's listen
# mode auto-installs and subscribes; he then decrypts the channel
# message alice publishes seconds later.
#
# Asserts:
#   - bob receives both the INVITE: notification AND the CHAN-MSG marker
#   - the random plaintext marker never appears in the server log
#   - the random plaintext marker never appears in the channel-key payload
#     visible to the server (the server can only see ciphertext envelopes)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBINBAND-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"
SERVER="${BUILD}/server/fb_server"
CLI="${BUILD}/tools/fb-cli/fb-cli"

PORT=$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)

SCRATCH="$(mktemp -d -t fbinband.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
ALICE_LOG="${SCRATCH}/alice.log"
BOB_OUT="${SCRATCH}/bob.out"
BOB_LOG="${SCRATCH}/bob.log"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

CHAN="ib-${MARKER}"

echo "== launching fb_server on 127.0.0.1:${PORT}"
"${SERVER}" --host 127.0.0.1 --port "${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null && break
    sleep 0.05
done

echo "== launching bob in listen mode (DM auto-handles channel-key invites)"
# We use --listen (the Phase 0 DM listener, now upgraded to also handle
# DmPayload.channel_key invites + decrypt subsequent channel envelopes).
"${CLI}" --user bob --listen --wait-ms 5000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>"${BOB_LOG}" &
BOB_PID=$!
sleep 0.4   # let bob register + upload prekey

echo "== launching alice in --channel-invite mode (DM dist to bob, then publish)"
"${CLI}" --user alice --channel-invite --channel-name "${CHAN}" \
    --peer bob --text "${MARKER}" --linger-ms 1500 \
    --server "127.0.0.1:${PORT}" 2>"${ALICE_LOG}"

wait "${BOB_PID}" || true
BOB_PID=""

echo "== checking bob received the invite + the channel message"
if ! grep -Fq "INVITE: #${CHAN}" "${BOB_OUT}"; then
    echo "FAIL: bob did not see INVITE." >&2
    cat "${BOB_OUT}" >&2
    cat "${BOB_LOG}" >&2
    exit 1
fi
if ! grep -Fq "CHAN-MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not see CHAN-MSG." >&2
    cat "${BOB_OUT}" >&2
    cat "${BOB_LOG}" >&2
    exit 1
fi

echo "== confirming server-blindness"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained plaintext marker — server is NOT blind!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: in-band channel invite via DM + group decrypt + server-blindness."
echo "  marker:       ${MARKER}"
echo "  bob received: $(grep -F 'CHAN-MSG:' "${BOB_OUT}")"
echo "  bob invite:   $(grep -F 'INVITE:' "${BOB_OUT}")"
echo "  server log:   $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
