#!/usr/bin/env bash
# End-to-end test for inline image/attachment DMs.
#
# alice --send-image sends a file as a DmPayload.attachment to bob;
# bob --listen --image-out writes the received bytes out. Assertions:
#   - bob prints IMG-RECEIVED
#   - the bytes bob wrote are byte-identical to what alice sent
#     (attachment survives ratchet encrypt → relay → decrypt intact)
#   - the server log never contains the file's marker (relay is blind to
#     attachment content, exactly as for text)
#
# The "image" is just bytes (a marker + random data) — fb-cli treats the
# content as opaque, so no real image tooling is needed.
#
# Usage: tools/e2e/image_roundtrip.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBIMG-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}" ]]    || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')

SCRATCH="$(mktemp -d -t fbe2e_img.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
BOB_OUT="${SCRATCH}/bob.stdout"
BOB_ERR="${SCRATCH}/bob.stderr"
ALICE_OUT="${SCRATCH}/alice.stdout"
ALICE_ERR="${SCRATCH}/alice.stderr"
IMG_IN="${SCRATCH}/send.bin"
IMG_OUT="${SCRATCH}/recv.bin"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

# Build a ~12 KB "image": the marker followed by random bytes. The marker
# lets us assert the relay never saw the content; the random tail makes
# the byte-identity check meaningful.
printf '%s' "${MARKER}" > "${IMG_IN}"
head -c 12288 /dev/urandom >> "${IMG_IN}"

echo "== launching fb_server on 127.0.0.1:${PORT}"
"${SERVER_BIN}" --host 127.0.0.1 --port "${PORT}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    if (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then break; fi
    sleep 0.05
done

echo "== launching fb-cli --listen as bob (--image-out)"
"${CLI_BIN}" --user bob --listen --image-out "${IMG_OUT}" --wait-ms 8000 \
    --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.4   # let bob register + upload bundle

echo "== launching fb-cli --send-image as alice"
"${CLI_BIN}" --user alice --send-image "${IMG_IN}" --peer bob \
    --server "127.0.0.1:${PORT}" >"${ALICE_OUT}" 2>"${ALICE_ERR}" || true

wait "${BOB_PID}" || true

dump() {
    echo "----- bob.stdout -----"   >&2; cat "${BOB_OUT}"   >&2
    echo "----- bob.stderr -----"   >&2; cat "${BOB_ERR}"   >&2
    echo "----- alice.stdout -----" >&2; cat "${ALICE_OUT}" >&2
    echo "----- alice.stderr -----" >&2; cat "${ALICE_ERR}" >&2
    echo "----- server.log -----"   >&2; cat "${SERVER_LOG}" >&2
}

echo "== asserting bob received the attachment"
if ! grep -q "IMG-RECEIVED:" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the attachment" >&2
    dump
    exit 1
fi

echo "== asserting received bytes are identical to what was sent"
if [[ ! -f "${IMG_OUT}" ]] || ! cmp -s "${IMG_IN}" "${IMG_OUT}"; then
    echo "FAIL: received attachment differs from the sent file" >&2
    echo "  sent: $(wc -c < "${IMG_IN}") bytes, recv: $(wc -c < "${IMG_OUT}" 2>/dev/null || echo missing)" >&2
    dump
    exit 1
fi

echo "== confirming server-blindness (marker must not appear in server log)"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained the attachment marker — relay is NOT blind!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: inline attachment DM round-trip (byte-identical, relay blind)."
echo "  marker:        ${MARKER}"
echo "  size:          $(wc -c < "${IMG_IN}") bytes"
echo "  bob:           $(grep -F 'IMG-RECEIVED:' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no content)"
