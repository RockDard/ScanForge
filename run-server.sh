#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

PYTHON_BIN="python3"
if [[ -x "$(dirname "${BASH_SOURCE[0]}")/.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "${BASH_SOURCE[0]}")/.venv/bin/python"
fi

HOST="${QA_PORTAL_HOST:-0.0.0.0}"
PORT="${QA_PORTAL_PORT:-8000}"
RELOAD="${QA_PORTAL_RELOAD:-1}"

UVICORN_ARGS=(qa_portal.app:app --host "$HOST" --port "$PORT")
if [[ "$RELOAD" == "1" ]]; then
  UVICORN_ARGS+=(--reload)
fi

"$PYTHON_BIN" -m uvicorn "${UVICORN_ARGS[@]}"
