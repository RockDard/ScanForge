#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PATH="$HOME/.local/bin:$PATH"
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

PYTHON_BIN="python3"
if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
fi

"$PYTHON_BIN" -m unittest discover -s "$SCRIPT_DIR/tests" -p "test_*.py"
bash -n "$SCRIPT_DIR/run-server.sh"
bash -n "$SCRIPT_DIR/run-worker.sh"
bash -n "$SCRIPT_DIR/run-sync-kb.sh"
if compgen -G "$SCRIPT_DIR/scripts/*.sh" >/dev/null; then
  bash -n "$SCRIPT_DIR"/scripts/*.sh
fi
"$SCRIPT_DIR/tests/test_123.sh"
