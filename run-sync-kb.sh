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

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec "$PYTHON_BIN" -m qa_portal.knowledge_base "$@"
fi

scanforge_assert_python_runtime "$ROOT_DIR"

"$PYTHON_BIN" -m qa_portal.knowledge_base "$@"
