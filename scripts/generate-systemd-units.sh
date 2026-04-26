#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR=""
DEFAULT_SERVICE_USER="${SUDO_USER:-${USER:-scanforge}}"
SERVICE_USER="${SCANFORGE_SERVICE_USER:-$DEFAULT_SERVICE_USER}"
SERVICE_GROUP="${SCANFORGE_SERVICE_GROUP:-$SERVICE_USER}"
SERVICE_HOST="${QA_PORTAL_HOST:-0.0.0.0}"
SERVICE_PORT="${QA_PORTAL_PORT:-8000}"
DATA_DIR="${QA_PORTAL_DATA_DIR:-$ROOT_DIR/data}"
ENV_FILE="/etc/scanforge/scanforge.env"
ALLOWED_HOSTS="${QA_PORTAL_ALLOWED_HOSTS:-}"
CORS_ORIGINS="${QA_PORTAL_CORS_ORIGINS:-}"
CORS_ALLOW_CREDENTIALS="${QA_PORTAL_CORS_ALLOW_CREDENTIALS:-0}"
AUTH_AUTO_SETUP="${QA_PORTAL_AUTH_AUTO_SETUP:-1}"
AUTH_BOOTSTRAP="${QA_PORTAL_AUTH_BOOTSTRAP:-1}"
AUTH_ADMIN_USER="${QA_PORTAL_ADMIN_USER:-admin}"

print_help() {
  cat <<'EOF'
Usage: ./scripts/generate-systemd-units.sh [--output-dir DIR] [--user USER] [--group GROUP]
                                           [--host HOST] [--port PORT] [--data-dir DIR]
                                           [--env-file PATH]

Generates scanforge-web.service, scanforge-worker.service, and scanforge.env
templates for a stable Linux systemd deployment. Without --output-dir the
files are printed to stdout.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      print_help
      exit 0
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { printf 'Missing value for --output-dir.\n' >&2; exit 1; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --user)
      [[ $# -ge 2 ]] || { printf 'Missing value for --user.\n' >&2; exit 1; }
      SERVICE_USER="$2"
      shift 2
      ;;
    --group)
      [[ $# -ge 2 ]] || { printf 'Missing value for --group.\n' >&2; exit 1; }
      SERVICE_GROUP="$2"
      shift 2
      ;;
    --host)
      [[ $# -ge 2 ]] || { printf 'Missing value for --host.\n' >&2; exit 1; }
      SERVICE_HOST="$2"
      shift 2
      ;;
    --port)
      [[ $# -ge 2 ]] || { printf 'Missing value for --port.\n' >&2; exit 1; }
      SERVICE_PORT="$2"
      shift 2
      ;;
    --data-dir)
      [[ $# -ge 2 ]] || { printf 'Missing value for --data-dir.\n' >&2; exit 1; }
      DATA_DIR="$2"
      shift 2
      ;;
    --env-file)
      [[ $# -ge 2 ]] || { printf 'Missing value for --env-file.\n' >&2; exit 1; }
      ENV_FILE="$2"
      shift 2
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      print_help >&2
      exit 1
      ;;
  esac
done

render_env() {
  cat <<EOF
QA_PORTAL_HOST=$(systemd_env_value "$SERVICE_HOST")
QA_PORTAL_PORT=$(systemd_env_value "$SERVICE_PORT")
QA_PORTAL_ALLOWED_HOSTS=$(systemd_env_value "$ALLOWED_HOSTS")
QA_PORTAL_CORS_ORIGINS=$(systemd_env_value "$CORS_ORIGINS")
QA_PORTAL_CORS_ALLOW_CREDENTIALS=$(systemd_env_value "$CORS_ALLOW_CREDENTIALS")
QA_PORTAL_AUTH_AUTO_SETUP=$(systemd_env_value "$AUTH_AUTO_SETUP")
QA_PORTAL_AUTH_BOOTSTRAP=$(systemd_env_value "$AUTH_BOOTSTRAP")
QA_PORTAL_ADMIN_USER=$(systemd_env_value "$AUTH_ADMIN_USER")
QA_PORTAL_RELOAD=0
QA_PORTAL_AUTOSTART_WORKER=0
QA_PORTAL_DATA_DIR=$(systemd_env_value "$DATA_DIR")
QA_PORTAL_WORKER_PROCESSES=auto
QA_PORTAL_WORKER_POLL_SECONDS=3
EOF
}

systemd_env_value() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

render_web_service() {
  cat <<EOF
[Unit]
Description=ScanForge web portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$ROOT_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=$ROOT_DIR/run-server.sh
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF
}

render_worker_service() {
  cat <<EOF
[Unit]
Description=ScanForge worker
After=network-online.target scanforge-web.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$ROOT_DIR
EnvironmentFile=-$ENV_FILE
ExecStart=$ROOT_DIR/run-worker.sh
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF
}

if [[ -n "$OUTPUT_DIR" ]]; then
  mkdir -p "$OUTPUT_DIR"
  render_env >"$OUTPUT_DIR/scanforge.env"
  render_web_service >"$OUTPUT_DIR/scanforge-web.service"
  render_worker_service >"$OUTPUT_DIR/scanforge-worker.service"
  printf 'Generated systemd files in %s\n' "$OUTPUT_DIR"
  printf 'Install example:\n'
  printf '  sudo install -Dm0644 %s/scanforge.env %s\n' "$OUTPUT_DIR" "$ENV_FILE"
  printf '  sudo install -Dm0644 %s/scanforge-web.service /etc/systemd/system/scanforge-web.service\n' "$OUTPUT_DIR"
  printf '  sudo install -Dm0644 %s/scanforge-worker.service /etc/systemd/system/scanforge-worker.service\n' "$OUTPUT_DIR"
  printf '  sudo systemctl daemon-reload && sudo systemctl enable --now scanforge-web scanforge-worker\n'
else
  printf '### scanforge.env\n'
  render_env
  printf '\n### scanforge-web.service\n'
  render_web_service
  printf '\n### scanforge-worker.service\n'
  render_worker_service
fi
