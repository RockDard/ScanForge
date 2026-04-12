#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"

# Общий runtime helper отвечает за выбор Python и подбор рабочего порта.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/scanforge-lib.sh"
scanforge_init_python "$ROOT_DIR"
scanforge_load_project_env "$ROOT_DIR"

HOST="${QA_PORTAL_HOST:-0.0.0.0}"
PORT="${QA_PORTAL_PORT:-8000}"
RELOAD="${QA_PORTAL_RELOAD:-1}"

scanforge_pick_port "$HOST" "$PORT" 8000 8100

HOST="$SCANFORGE_HOST"
PORT="$SCANFORGE_PORT"
URL="$SCANFORGE_URL"

if [[ "$SCANFORGE_PICK_STATUS" == "scanforge-running" || "$SCANFORGE_PICK_STATUS" == "fallback-running-scanforge" ]]; then
  printf 'ScanForge уже отвечает по адресу %s.\n' "$URL"
  exit 0
fi

if [[ "$SCANFORGE_PICK_STATUS" == "preferred-occupied-foreign" ]]; then
  printf 'Предпочтительный порт занят сторонним сервисом. Переключение на %s.\n' "$URL" >&2
fi

printf 'ScanForge запускается по адресу %s.\n' "$URL"

UVICORN_ARGS=(qa_portal.app:app --host "$HOST" --port "$PORT")
if [[ "$RELOAD" == "1" ]]; then
  UVICORN_ARGS+=(--reload)
fi

exec "$PYTHON_BIN" -m uvicorn "${UVICORN_ARGS[@]}"
