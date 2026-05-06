#!/usr/bin/env bash
# Tiny static dev server for the FinBit web UI.
#
# Serves client-web/ at http://127.0.0.1:8080 so the browser can fetch
# both ui/index.html and the sibling build/finbit.{mjs,wasm}.
#
# Open: http://127.0.0.1:8080/ui/

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}/client-web"

[[ -f build/finbit.mjs ]] || {
    echo "WARN: build/finbit.mjs missing — run scripts/build-wasm.sh first" >&2
}

PORT="${PORT:-8080}"
echo "FinBit web UI → http://127.0.0.1:${PORT}/ui/"
exec python3 -m http.server "${PORT}" --bind 127.0.0.1
