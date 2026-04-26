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
scanforge_assert_python_runtime "$ROOT_DIR"

HOST="${QA_PORTAL_HOST:-0.0.0.0}"
PORT="${QA_PORTAL_PORT:-8000}"
RELOAD="${QA_PORTAL_RELOAD:-1}"

scanforge_pick_port "$HOST" "$PORT" 8000 8100

HOST="$SCANFORGE_HOST"
PORT="$SCANFORGE_PORT"
URL="$SCANFORGE_URL"
export QA_PORTAL_HOST="$HOST"
export QA_PORTAL_PORT="$PORT"

if [[ "$SCANFORGE_PICK_STATUS" == "scanforge-running" || "$SCANFORGE_PICK_STATUS" == "fallback-running-scanforge" ]]; then
  printf 'ScanForge уже отвечает по адресу %s (слушает %s:%s).\n' "$URL" "$HOST" "$PORT"
  exit 0
fi

if [[ "$SCANFORGE_PICK_STATUS" == "preferred-occupied-foreign" ]]; then
  printf 'Предпочтительный порт занят сторонним сервисом. Переключение на %s.\n' "$URL" >&2
fi

printf 'ScanForge запускается по адресу %s (слушает %s:%s).\n' "$URL" "$HOST" "$PORT"

if [[ -z "${QA_PORTAL_AUTH_ENABLED+x}" && "${QA_PORTAL_AUTH_AUTO_SETUP:-1}" != "0" && -z "${QA_PORTAL_ADMIN_PASSWORD:-}" ]]; then
  case "$HOST" in
    127.*|localhost|::1|\[::1\])
      ;;
    *)
      export QA_PORTAL_AUTH_ENABLED=1
      export QA_PORTAL_AUTH_BOOTSTRAP="${QA_PORTAL_AUTH_BOOTSTRAP:-1}"
      "$PYTHON_BIN" -m qa_portal.auth bootstrap >&2
      ;;
  esac
fi

UVICORN_ARGS=(qa_portal.app:app --host "$HOST" --port "$PORT")
if [[ "$RELOAD" == "1" ]]; then
  UVICORN_ARGS+=(--reload)
fi

exec "$PYTHON_BIN" -m uvicorn "${UVICORN_ARGS[@]}"
