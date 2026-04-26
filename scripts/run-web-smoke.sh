#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/run-web-smoke.sh [--existing-url URL]

Run the optional ScanForge web smoke stage.
EOF
  exit 0
fi

# Optional smoke-stage использует тот же Python-контур, что и основные entrypoint-скрипты.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"
scanforge_assert_python_runtime "$ROOT_DIR"

exec "$PYTHON_BIN" -m qa_portal.web_smoke "$@"
