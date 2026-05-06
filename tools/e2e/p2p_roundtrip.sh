#!/usr/bin/env bash
# Server-less end-to-end test: 4 fb-cli peers in P2P mode form a small
# gossipsub overlay, alice publishes one E2E-encrypted group message, bob
# and carol both receive it via gossip relay through dave (the bootstrap).
# No central server is involved.
#
# Topology:
#
#                 dave (bootstrap)
#                  /  |  \
#                 /   |   \
#              alice bob  carol
#
# alice -> dave -> bob & carol
# (A gossipsub-style 1-hop fanout from the bootstrap node.)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-${REPO_ROOT}/build/system}"
MARKER="${2:-FBP2P-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')-MAGIC}"
CLI="${BUILD}/tools/fb-cli/fb-cli"
[[ -x "${CLI}" ]] || { echo "FAIL: fb-cli not built at ${CLI}" >&2; exit 1; }

# Pick four free ports.
PORTS=$(python3 - <<'PY'
import socket
out = []
for _ in range(4):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); out.append(s.getsockname()[1]); s.close()
print(" ".join(str(p) for p in out))
PY
)
read -r DAVE_PORT ALICE_PORT BOB_PORT CAROL_PORT <<< "${PORTS}"

SCRATCH="$(mktemp -d -t fbp2p.XXXXXX)"
DIST="${SCRATCH}/alice.dist"
DAVE_LOG="${SCRATCH}/dave.log"
ALICE_LOG="${SCRATCH}/alice.log"
BOB_OUT="${SCRATCH}/bob.stdout"
BOB_LOG="${SCRATCH}/bob.log"
CAROL_OUT="${SCRATCH}/carol.stdout"
CAROL_LOG="${SCRATCH}/carol.log"

cleanup() {
    for v in DAVE_PID ALICE_PID BOB_PID CAROL_PID; do
        if [[ -n "${!v:-}" ]]; then kill "${!v}" 2>/dev/null || true; fi
    done
    rm -rf "${SCRATCH}"
}
trap cleanup EXIT

CHAN="p2p-${MARKER}"

echo "== launching dave (bootstrap p2p relay — no dist, no decrypt)"
"${CLI}" --user dave --p2p-relay --channel-name "${CHAN}" \
    --p2p-port "${DAVE_PORT}" --wait-ms 6000 \
    >"${SCRATCH}/dave.stdout" 2>"${DAVE_LOG}" &
DAVE_PID=$!
sleep 0.2

echo "== launching bob + carol (dial dave)"
"${CLI}" --user bob --p2p-listen --channel-name "${CHAN}" \
    --dist-file "${DIST}" --p2p-port "${BOB_PORT}" --p2p-dial "127.0.0.1:${DAVE_PORT}" \
    --wait-ms 5000 >"${BOB_OUT}" 2>"${BOB_LOG}" &
BOB_PID=$!
"${CLI}" --user carol --p2p-listen --channel-name "${CHAN}" \
    --dist-file "${DIST}" --p2p-port "${CAROL_PORT}" --p2p-dial "127.0.0.1:${DAVE_PORT}" \
    --wait-ms 5000 >"${CAROL_OUT}" 2>"${CAROL_LOG}" &
CAROL_PID=$!

sleep 0.6   # let everyone subscribe + propagate subscription

echo "== launching alice (p2p-create + publish)"
"${CLI}" --user alice --p2p-create --channel-name "${CHAN}" \
    --dist-file "${DIST}" --text "${MARKER}" --linger-ms 1500 \
    --p2p-port "${ALICE_PORT}" --p2p-dial "127.0.0.1:${DAVE_PORT}" \
    >"${SCRATCH}/alice.stdout" 2>"${ALICE_LOG}"

wait "${BOB_PID}"   || true
wait "${CAROL_PID}" || true
wait "${DAVE_PID}"  || true

echo "== checking bob received via gossip"
if ! grep -Fq "P2P-MSG: ${MARKER}" "${BOB_OUT}"; then
    echo "FAIL: bob did not see P2P-MSG. bob.stdout:" >&2; cat "${BOB_OUT}" >&2
    echo "----- bob.log -----" >&2; cat "${BOB_LOG}" >&2
    echo "----- dave.log -----" >&2; cat "${DAVE_LOG}" >&2
    exit 1
fi
echo "== checking carol received via gossip"
if ! grep -Fq "P2P-MSG: ${MARKER}" "${CAROL_OUT}"; then
    echo "FAIL: carol did not see P2P-MSG. carol.stdout:" >&2; cat "${CAROL_OUT}" >&2
    exit 1
fi

echo "== confirming server-blindness on the relay path (dave saw only ciphertext)"
# Dave is just a relay; he subscribed but cannot decrypt (no SenderKeys distribution).
if grep -Fq "${MARKER}" "${DAVE_LOG}"; then
    echo "FAIL: dave's log contained the plaintext marker — relay was NOT blind!" >&2
    cat "${DAVE_LOG}" >&2
    exit 1
fi
# And dave's stdout (which would print P2P-MSG: ... if he could decrypt) should
# also be silent for the marker.
if grep -Fq "P2P-MSG: ${MARKER}" "${SCRATCH}/dave.stdout"; then
    echo "FAIL: dave decrypted the marker — relay was NOT blind!" >&2
    exit 1
fi

echo "PASS: P2P fanout via gossip + relay blindness."
echo "  marker:        ${MARKER}"
echo "  bob received:  $(grep -F 'P2P-MSG:' "${BOB_OUT}")"
echo "  carol received: $(grep -F 'P2P-MSG:' "${CAROL_OUT}")"
echo "  dave (relay): $(wc -l < "${DAVE_LOG}") log lines, no plaintext"
