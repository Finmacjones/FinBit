#!/usr/bin/env bash
# End-to-end test for Tier-3 domain-fronting (SNI / Host decoupling).
#
# The server's TLS cert is issued for a FRONT domain only
# (SAN=front.finbit.test, NOT 127.0.0.1). fb-cli connects to the IP
# 127.0.0.1 but:
#   - presents TLS SNI = front.finbit.test       (--front)
#   - sends WS Host header = real.backend.test   (--ws-host)
#   - validates the cert against the system/--tls-ca trust WITH
#     hostname verification ON (no --tls-insecure-skip-verify)
#
# Because the cert only matches the front domain, a successful TLS
# handshake + DM round-trip PROVES the SNI presented was the front
# (any other SNI would fail hostname verification against a front-only
# cert). The Host header is independently set to a different backend —
# exactly the domain-fronting shape a censor cannot distinguish from a
# normal HTTPS fetch of front.finbit.test.
#
# Usage: tools/e2e/fronting_dm_roundtrip.sh [build-dir] [secret-marker]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBE2E-FRONT-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"

SERVER_BIN="${BUILD}/server/fb_server"
CLI_BIN="${BUILD}/tools/fb-cli/fb-cli"

[[ -x "${SERVER_BIN}" ]] || { echo "FAIL: server not built at ${SERVER_BIN}" >&2; exit 1; }
[[ -x "${CLI_BIN}"    ]] || { echo "FAIL: fb-cli not built at ${CLI_BIN}"    >&2; exit 1; }
command -v openssl >/dev/null || { echo "FAIL: openssl not installed" >&2; exit 1; }

FRONT_DOMAIN="front.finbit.test"
REAL_BACKEND="real.backend.test"

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
TLS_PORT=$(free_port)
PLAIN_PORT=$(free_port)

SCRATCH="$(mktemp -d -t fbe2e_front.XXXXXX)"
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

# Cert for the FRONT domain ONLY — deliberately no 127.0.0.1 SAN, so a
# connection that did NOT present SNI=front would fail verification.
echo "== generating cert for FRONT domain only (${FRONT_DOMAIN})"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${KEY}" -out "${CERT}" \
    -days 1 -subj "/CN=${FRONT_DOMAIN}" \
    -addext "subjectAltName=DNS:${FRONT_DOMAIN}" \
    >/dev/null 2>&1

echo "== launching fb_server --tls-port ${TLS_PORT}"
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

# Connect to the IP, present SNI=front (validated against the front-only
# cert), Host=real-backend. No --tls-insecure-skip-verify → hostname
# verification is ON.
echo "== launching fb-cli listen as bob (fronted: SNI=${FRONT_DOMAIN}, Host=${REAL_BACKEND})"
"${CLI_BIN}" --user bob --listen --wait-ms 5000 \
    --server "127.0.0.1:${TLS_PORT}" \
    --wss --tls-ca "${CERT}" \
    --front "${FRONT_DOMAIN}" --ws-host "${REAL_BACKEND}" \
    >"${BOB_OUT}" 2>"${BOB_ERR}" &
BOB_PID=$!
sleep 0.5

echo "== launching fb-cli send as alice (fronted)"
"${CLI_BIN}" --user alice --send --peer bob --text "${MARKER}" \
    --server "127.0.0.1:${TLS_PORT}" \
    --wss --tls-ca "${CERT}" \
    --front "${FRONT_DOMAIN}" --ws-host "${REAL_BACKEND}" \
    2>"${ALICE_ERR}"

wait "${BOB_PID}" || true

echo "== inspecting bob output"
if ! grep -Fq "MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not receive the marker over the fronted connection" >&2
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

# Negative control: WITHOUT --front, the SNI defaults to 127.0.0.1,
# which the front-only cert does NOT match — TLS verification must fail,
# so bob never receives the marker. This proves --front is what made the
# positive case work (i.e. the SNI really was the front domain).
echo "== negative control: same cert, NO --front (SNI=127.0.0.1) must fail"
NEG_OUT="${SCRATCH}/neg.stdout"
NEG_ERR="${SCRATCH}/neg.stderr"
"${CLI_BIN}" --user carol --listen --wait-ms 2000 \
    --server "127.0.0.1:${TLS_PORT}" \
    --wss --tls-ca "${CERT}" \
    >"${NEG_OUT}" 2>"${NEG_ERR}" &
NEG_PID=$!
"${CLI_BIN}" --user dave --send --peer carol --text "SHOULD-NOT-ARRIVE" \
    --server "127.0.0.1:${TLS_PORT}" \
    --wss --tls-ca "${CERT}" \
    >/dev/null 2>&1 || true
wait "${NEG_PID}" 2>/dev/null || true
if grep -Fq "MSG: SHOULD-NOT-ARRIVE" "${NEG_OUT}"; then
    echo "FAIL: connection succeeded WITHOUT --front against a front-only cert" >&2
    echo "      (hostname verification should have rejected SNI=127.0.0.1)" >&2
    exit 1
fi
echo "  OK connection without --front correctly failed cert verification"

echo "PASS: domain-fronting DM round-trip (SNI=${FRONT_DOMAIN}, Host=${REAL_BACKEND})."
echo "  marker:        ${MARKER}"
echo "  tls_port:      ${TLS_PORT}"
echo "  bob received:  $(grep -F 'MSG:' "${BOB_OUT}")"
echo "  server log:    $(wc -c < "${SERVER_LOG}") bytes (no plaintext)"
