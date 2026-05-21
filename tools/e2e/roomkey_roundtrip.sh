#!/usr/bin/env bash
# End-to-end test for group-call room-key distribution (Lever B keying).
#
# alice --send-roomkey picks a random 32-byte room_secret and DMs it to bob
# inside a DmPayload.room_key sealed by the Double Ratchet; bob --listen
# decrypts and prints it. Assertions:
#   - alice prints ROOMKEY-SENT with the secret she generated
#   - bob prints ROOMKEY with a secret
#   - the secret bob received is byte-identical to the one alice sent
#     (survives ratchet encrypt → relay → decrypt intact)
#   - the server log never contains the secret hex (the relay — and so any
#     media forwarder — is blind to the room key, which is the whole point:
#     forwarders relay SFrame ciphertext they can't read)
#
# This is the keying half of Lever B: from this shared room_secret each
# member derives every sender's SFrame key via derive_room_sframe_key.
#
# Usage: tools/e2e/roomkey_roundtrip.sh [build-dir]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
EPOCH="7"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}" ]]    || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')

SCRATCH="$(mktemp -d -t fbe2e_rk.XXXXXX)"
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

echo "== launching fb-cli --listen as bob"
"${CLI_BIN}" --user bob --listen --wait-ms 8000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.4   # let bob register + upload bundle

echo "== launching fb-cli --send-roomkey as alice (epoch ${EPOCH})"
"${CLI_BIN}" --user alice --send-roomkey --room-epoch "${EPOCH}" --peer bob \
    --server "127.0.0.1:${PORT}" >"${ALICE_OUT}" 2>"${ALICE_ERR}" || true

wait "${BOB_PID}" || true

dump() {
    echo "----- bob.stdout -----"   >&2; cat "${BOB_OUT}"   >&2
    echo "----- bob.stderr -----"   >&2; cat "${BOB_ERR}"   >&2
    echo "----- alice.stdout -----" >&2; cat "${ALICE_OUT}" >&2
    echo "----- alice.stderr -----" >&2; cat "${ALICE_ERR}" >&2
    echo "----- server.log -----"   >&2; cat "${SERVER_LOG}" >&2
}

echo "== asserting alice sent a room key"
SENT_SECRET="$(grep -oE 'ROOMKEY-SENT: epoch=[0-9]+ secret=[0-9a-f]+' "${ALICE_OUT}" | grep -oE 'secret=[0-9a-f]+' | cut -d= -f2 || true)"
if [[ -z "${SENT_SECRET}" ]]; then
    echo "FAIL: alice did not report ROOMKEY-SENT" >&2
    dump
    exit 1
fi

echo "== asserting bob received the room key"
RECV_SECRET="$(grep -oE 'ROOMKEY: epoch=[0-9]+ secret=[0-9a-f]+' "${BOB_OUT}" | grep -oE 'secret=[0-9a-f]+' | cut -d= -f2 || true)"
if [[ -z "${RECV_SECRET}" ]]; then
    echo "FAIL: bob did not receive the room key" >&2
    dump
    exit 1
fi

echo "== asserting received secret is identical to the sent secret"
if [[ "${SENT_SECRET}" != "${RECV_SECRET}" ]]; then
    echo "FAIL: room secret mismatch" >&2
    echo "  sent: ${SENT_SECRET}" >&2
    echo "  recv: ${RECV_SECRET}" >&2
    dump
    exit 1
fi

echo "== asserting bob saw the right epoch"
if ! grep -q "ROOMKEY: epoch=${EPOCH} " "${BOB_OUT}"; then
    echo "FAIL: bob received the wrong epoch (expected ${EPOCH})" >&2
    dump
    exit 1
fi

echo "== confirming server-blindness (secret must not appear in server log)"
if grep -Fq "${SENT_SECRET}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained the room secret — relay is NOT blind!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: room-key distribution round-trip (byte-identical, relay blind)."
echo "  epoch:      ${EPOCH}"
echo "  secret:     ${SENT_SECRET}"
echo "  server log: $(wc -c < "${SERVER_LOG}") bytes (no secret)"
