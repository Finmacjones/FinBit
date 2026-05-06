#!/usr/bin/env bash
# Full server-state persistence test: directory + prekey bundles also
# survive a restart, not just the offline queue.
#
# Round 1 (server-A):
#   - bob registers + uploads prekey, then disconnects
#   - server-A is killed without alice ever connecting (so bob's bundle
#     is ONLY persisted to SQLite, not held in some other process's RAM)
#
# Round 2 (server-B, fresh process, same DB):
#   - alice connects and sends DM to "bob"
#   - server-B must:
#       a) resolve "bob" -> pubkey from the persisted directory
#       b) return bob's prekey bundle from the persisted store
#       c) queue the envelope (bob is offline)
#   - bob comes online, drains the queued envelope, decrypts the marker

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBSRV-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"
SERVER="${BUILD}/server/fb_server"
CLI="${BUILD}/tools/fb-cli/fb-cli"

PORT=$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0))
print(s.getsockname()[1]); s.close()
PY
)
SCRATCH="$(mktemp -d -t fbsrv.XXXXXX)"
DB="${SCRATCH}/srv.db"
LOG_A="${SCRATCH}/server-A.log"
LOG_B="${SCRATCH}/server-B.log"
ALICE_LOG="${SCRATCH}/alice.log"
BOB_OUT="${SCRATCH}/bob.out"
BOB_LOG="${SCRATCH}/bob.log"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

# ---- ROUND 1: server-A ------------------------------------------------------
echo "== server-A on 127.0.0.1:${PORT}, db=${DB}"
"${SERVER}" --host 127.0.0.1 --port "${PORT}" --offline-db "${DB}" >"${LOG_A}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null && break; sleep 0.05; done

echo "== bob registers + uploads prekey to server-A"
"${CLI}" --user bob --listen --wait-ms 600 --server "127.0.0.1:${PORT}" >/dev/null 2>>"${BOB_LOG}"

echo "== killing server-A *before* alice ever connects"
kill "${SERVER_PID}"
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""

# ---- ROUND 2: server-B reading the same DB ---------------------------------
echo "== server-B (fresh process) on same db"
"${SERVER}" --host 127.0.0.1 --port "${PORT}" --offline-db "${DB}" >"${LOG_B}" 2>&1 &
SERVER_PID=$!
for _ in {1..40}; do (echo > /dev/tcp/127.0.0.1/${PORT}) 2>/dev/null && break; sleep 0.05; done

echo "== alice sends to bob (server-B must look bob up from persisted directory)"
"${CLI}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${PORT}" 2>"${ALICE_LOG}"

echo "== bob comes back online, drains the offline envelope"
"${CLI}" --user bob --listen --wait-ms 3000 --server "127.0.0.1:${PORT}" \
    >"${BOB_OUT}" 2>>"${BOB_LOG}" &
BOB_PID=$!
wait "${BOB_PID}"
BOB_PID=""

if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not see the queued message after full server restart" >&2
    echo "--- alice.log ---" >&2; cat "${ALICE_LOG}" >&2
    echo "--- bob.out ---" >&2; cat "${BOB_OUT}" >&2
    echo "--- bob.log ---" >&2; cat "${BOB_LOG}" >&2
    echo "--- server-A.log ---" >&2; cat "${LOG_A}" >&2
    echo "--- server-B.log ---" >&2; cat "${LOG_B}" >&2
    exit 1
fi
if grep -Fq "${MARKER}" "${LOG_A}" || grep -Fq "${MARKER}" "${LOG_B}"; then
    echo "FAIL: a server log contained the plaintext marker" >&2
    exit 1
fi

echo "PASS: directory + prekey + offline-queue all persisted across restart."
echo "  marker:       ${MARKER}"
echo "  bob received: $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  db size:      $(wc -c < "${DB}") bytes"
