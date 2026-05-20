#!/usr/bin/env bash
# End-to-end test for the NATIVE WebSocket-over-TLS path (Tier-2
# censorship-resistance mimicry). Unlike wss_dm_roundtrip.sh — which
# uses --tls-raw-port (raw frames under TLS) — this drives the server's
# --tls-port (real RFC 6455 WebSocket under TLS) with fb-cli --wss, so
# the native client performs an actual HTTP/1.1 Upgrade handshake and
# exchanges masked WS binary frames, exactly as a browser would.
#
# Assertions:
#   - bob (listening, --wss) receives the marker plaintext
#   - the server's plaintext log NEVER contains the marker (server stays
#     blind: the WS frame only carries the encrypted ratchet payload)
#
# Usage: tools/e2e/wss_native_dm_roundtrip.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBE2E-WSSNATIVE-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}"    ]] || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }
command -v openssl >/dev/null || { echo "FAIL: openssl not installed" >&2; exit 1; }

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

TLS_PORT=$(free_port)
PLAIN_PORT=$(free_port)

SCRATCH="$(mktemp -d -t fbe2e_wssnative.XXXXXX)"
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

echo "== generating self-signed cert for localhost"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${KEY}" -out "${CERT}" \
    -days 1 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1

echo "== launching fb_server with --tls-port ${TLS_PORT} (real WSS)"
"${SERVER_BIN}" \
    --host 127.0.0.1 \
    --port "${PLAIN_PORT}" \
    --tls-port "${TLS_PORT}" \
    --tls-cert "${CERT}" \
    --tls-key  "${KEY}" \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in {1..40}; do
    if (echo > /dev/tcp/127.0.0.1/${TLS_PORT}) 2>/dev/null; then break; fi
    sleep 0.05
done

echo "== launching fb-cli listen as bob (--wss)"
"${CLI_BIN}" --user bob --listen --wait-ms 5000 \
    --server "127.0.0.1:${TLS_PORT}" \
    --wss --tls-ca "${CERT}" --tls-sni localhost \
    >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.5   # TLS handshake + WS upgrade + register

echo "== launching fb-cli send as alice (--wss)"
"${CLI_BIN}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${TLS_PORT}" \
    --wss --tls-ca "${CERT}" --tls-sni localhost \
    2>"${ALICE_ERR}"

wait "${BOB_PID}" || true

echo "== inspecting bob output"
if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the marker over native WSS" >&2
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

echo "PASS: end-to-end DM round-trip over NATIVE WSS (--tls-port + fb-cli --wss)."
echo "  marker:        ${MARKER}"
echo "  tls_port:      ${TLS_PORT}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
