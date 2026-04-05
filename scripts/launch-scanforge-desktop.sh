#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT_DIR/.env"
  set +a
fi

HOST="${QA_PORTAL_HOST:-127.0.0.1}"
PORT="${QA_PORTAL_PORT:-8000}"
URL="http://${HOST}:${PORT}"

healthcheck() {
  python3 - "$HOST" "$PORT" <<'PY'
import json
import sys
import urllib.request

host, port = sys.argv[1], sys.argv[2]
url = f"http://{host}:{port}/health"

try:
    with urllib.request.urlopen(url, timeout=2) as response:
        payload = json.loads(response.read().decode("utf-8"))
except Exception:
    raise SystemExit(1)

raise SystemExit(0 if payload.get("status") == "ok" else 1)
PY
}

open_browser() {
  if [[ "${SCANFORGE_SKIP_BROWSER:-0}" == "1" ]]; then
    return 0
  fi
  if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    return 0
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
  fi
}

if healthcheck; then
  open_browser
  exit 0
fi

if ! command -v pkexec >/dev/null 2>&1; then
  printf 'Не найден pkexec. Установите polkit или запустите ScanForge вручную.\n' >&2
  exit 1
fi

pkexec "$ROOT_DIR/scripts/start-scanforge-admin.sh"

for _ in $(seq 1 60); do
  if healthcheck; then
    open_browser
    exit 0
  fi
  sleep 1
done

printf 'ScanForge стартовал, но веб-интерфейс не ответил по адресу %s.\n' "$URL" >&2
exit 1
