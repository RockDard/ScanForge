#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"

# Общий helper подготавливает Python и PYTHONPATH независимо от cwd запуска.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

POLL_SECONDS="${QA_PORTAL_WORKER_POLL_SECONDS:-3}"
WORKER_PROCESSES="${QA_PORTAL_WORKER_PROCESSES:-auto}"

"$PYTHON_BIN" -m qa_portal.worker pool --poll-seconds "$POLL_SECONDS" --processes "$WORKER_PROCESSES"
