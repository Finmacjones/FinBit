#!/usr/bin/env bash
# Persistent offline queue test:
#   1. Start server with --offline-db
#   2. Alice sends DM while bob is OFFLINE — server queues to SQLite
#   3. Kill the server entirely
#   4. Restart server pointing at the same --offline-db
#   5. Bring bob online — he must receive the queued message after the
#      restart, proving the queue survived process death.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBOFFLINE-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"
SERVER="${BUILD}/server/fb_server"
CLI="${BUILD}/tools/fb-cli/fb-cli"

PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
PY
)
SCRATCH="$(mktemp -d -t fboffline.XXXXXX)"
DB="${SCRATCH}/offline.db"
LOG1="${SCRATCH}/server1.log"
LOG2="${SCRATCH}/server2.log"
ALICE_LOG="${SCRATCH}/alice.log"
BOB_OUT="${SCRATCH}/bob.out"
BOB_LOG="${SCRATCH}/bob.log"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

echo "== launching server (round 1) on 127.0.0.1:${PORT}, offline-db=${DB}"
"${SERVER}" --host 127.0.0.1 --port "${PORT}" --offline-db "${DB}" >"${LOG1}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null && break
    sleep 0.05
done

echo "== alice publishes prekey (so server knows bob's pubkey -> offline routing) THEN bob registers"
# We need bob to register at least once so the server knows his pubkey for
# alice's send. Bob disconnects after registration. Then alice sends; server
# queues for bob.
"${CLI}" --user bob --listen --wait-ms 600 --server "127.0.0.1:${PORT}" >/dev/null 2>>"${BOB_LOG}"

echo "== alice sends DM with bob OFFLINE — must hit the persistent queue"
"${CLI}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${PORT}" 2>>"${ALICE_LOG}"

echo "== killing server (round 1)"
kill "${SERVER_PID}"
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""

echo "== restarting server (round 2) reading the SAME offline DB"
"${SERVER}" --host 127.0.0.1 --port "${PORT}" --offline-db "${DB}" >"${LOG2}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do
    (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null && break
    sleep 0.05
done

echo "== bob comes back online after the restart"
"${CLI}" --user bob --listen --wait-ms 3000 --server "127.0.0.1:${PORT}" >"${BOB_OUT}" 2>>"${BOB_LOG}" &
BOB_PID=$!
wait "${BOB_PID}"
BOB_PID=""

if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the queued message after server restart" >&2
    echo "--- bob.out ---" >&2; cat "${BOB_OUT}" >&2
    echo "--- bob.log ---" >&2; cat "${BOB_LOG}" >&2
    echo "--- server1.log ---" >&2; cat "${LOG1}" >&2
    echo "--- server2.log ---" >&2; cat "${LOG2}" >&2
    exit 1
fi
if grep -Fq "${MARKER}" "${LOG1}" || grep -Fq "${MARKER}" "${LOG2}"; then
    echo "FAIL: server log contained plaintext marker" >&2
    exit 1
fi

echo "PASS: persistent offline queue survives server restart + server-blindness."
echo "  marker:        ${MARKER}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  db file size:  $(wc -c < "${DB}") bytes"
