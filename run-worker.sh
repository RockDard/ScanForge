#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

PYTHON_BIN="python3"
if [[ -x "$(dirname "${BASH_SOURCE[0]}")/.venv/bin/python" ]]; then
  PYTHON_BIN="$(dirname "${BASH_SOURCE[0]}")/.venv/bin/python"
fi

POLL_SECONDS="${QA_PORTAL_WORKER_POLL_SECONDS:-3}"
WORKER_PROCESSES="${QA_PORTAL_WORKER_PROCESSES:-auto}"

"$PYTHON_BIN" -m qa_portal.worker pool --poll-seconds "$POLL_SECONDS" --processes "$WORKER_PROCESSES"
