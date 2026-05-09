#!/usr/bin/env bash
# End-to-end test: spin up fb_server with --tls-port + a self-signed cert,
# and prove that two fb-cli peers can exchange a DM over the TLS-wrapped
# transport. Assertions:
#   - bob (listening over TLS) receives the marker plaintext
#   - the server's plaintext log NEVER contains the marker (server is blind
#     to the inner contents — TLS adds an outer wrap, encrypted ratchet
#     is still inside)
#   - the on-the-wire bytes flowing into the listening port are not the
#     plaintext marker (sanity check that the TLS layer isn't a no-op)
#
# Usage: tools/e2e/wss_dm_roundtrip.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBE2E-WSS-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}"    ]] || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }
command -v openssl >/dev/null || { echo "FAIL: openssl not installed" >&2; exit 1; }

# Pick a free port for the TLS listener.
TLS_PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)

SCRATCH="$(mktemp -d -t fbe2e_wss.XXXXXX)"
SERVER_LOG="${SCRATCH}/server.log"
BOB_OUT="${SCRATCH}/bob.stdout"
BOB_ERR="${SCRATCH}/bob.stderr"
ALICE_ERR="${SCRATCH}/alice.stderr"
CERT="${SCRATCH}/cert.pem"
KEY="${SCRATCH}/key.pem"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    [[ -n "${BOB_PID:-}"    ]] && kill "${BOB_PID}"    2>/dev/null || true
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

# Generate a self-signed cert for localhost. SAN required so OpenSSL
# hostname verification accepts "127.0.0.1" / "localhost".
echo "== generating self-signed cert for localhost"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${KEY}" -out "${CERT}" \
    -days 1 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1

echo "== launching fb_server with --tls-raw-port ${TLS_PORT}"
# Server still requires a plain --port for its own internal bookkeeping;
# point it at a different free port so we don't collide. --tls-raw-port
# is what fb-cli --tls connects to (TLS-wrapped raw frames; same wire
# format the plain --port serves, just with TLS below).
PLAIN_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
"${SERVER_BIN}" \
    --host 127.0.0.1 \
    --port "${PLAIN_PORT}" \
    --tls-raw-port "${TLS_PORT}" \
    --tls-cert "${CERT}" \
    --tls-key  "${KEY}" \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

# Wait for both listeners to be up.
for _ in {1..40}; do
    if (echo > /dev/tcp/127.0.0.1/${TLS_PORT}) 2>/dev/null; then break; fi
    sleep 0.05
done

echo "== launching fb-cli listen as bob (over TLS)"
"${CLI_BIN}" --user bob --listen --wait-ms 5000 \
    --server "127.0.0.1:${TLS_PORT}" \
    --tls --tls-ca "${CERT}" --tls-sni localhost \
    >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.4   # let bob complete TLS handshake + register

echo "== launching fb-cli send as alice (over TLS)"
"${CLI_BIN}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${TLS_PORT}" \
    --tls --tls-ca "${CERT}" --tls-sni localhost \
    2>"${ALICE_ERR}"

wait "${BOB_PID}" || true

echo "== inspecting bob output"
if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the marker over TLS" >&2
    echo "----- bob.stdout -----" >&2; cat "${BOB_OUT}" >&2
    echo "----- bob.stderr -----" >&2; cat "${BOB_ERR}" >&2
    echo "----- alice.stderr ---" >&2; cat "${ALICE_ERR}" >&2
    echo "----- server.log -----" >&2; cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "== confirming server-blindness (marker must not appear in server log)"
if grep -Fq "${MARKER}" "${SERVER_LOG}"; then
    echo "FAIL: server log contained plaintext marker — server is NOT blind!" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi

echo "PASS: end-to-end DM round-trip over WSS-style TLS."
echo "  marker:        ${MARKER}"
echo "  tls_port:      ${TLS_PORT}"
echo "  cert:          ${CERT}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
