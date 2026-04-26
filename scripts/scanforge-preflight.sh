#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Общий helper подготавливает Python и PYTHONPATH так же, как и основные entrypoint-скрипты.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

exec "$PYTHON_BIN" -m qa_portal.environment preflight --root "$ROOT_DIR" "$@"
