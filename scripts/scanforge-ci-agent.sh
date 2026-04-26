#!/usr/bin/env bash
set -euo pipefail

# Простой CLI-агент для CI: отправляет архив проекта в ScanForge и прикладывает
# контекст репозитория/пайплайна, чтобы отчеты содержали ссылку на источник запуска.

print_help() {
  cat <<'EOF'
Usage:
  ./scripts/scanforge-ci-agent.sh <scanforge-url> <upload-path> [mode] [preset]

Environment variables:
  SCANFORGE_NAME
  SCANFORGE_INTEGRATION_PROVIDER
  SCANFORGE_REPOSITORY_URL
  SCANFORGE_BRANCH
  SCANFORGE_COMMIT_SHA
  SCANFORGE_PIPELINE_URL
  SCANFORGE_MERGE_REQUEST
  SCANFORGE_RETEST_SCOPE
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  print_help
  exit 0
fi

if [[ $# -lt 2 ]]; then
  print_help >&2
  exit 1
fi

SCANFORGE_URL="${1%/}"
UPLOAD_PATH="$2"
MODE="${3:-full_scan}"
PRESET="${4:-balanced}"

if [[ ! -f "$UPLOAD_PATH" ]]; then
  printf 'Upload file not found: %s\n' "$UPLOAD_PATH" >&2
  exit 1
fi

JOB_NAME="${SCANFORGE_NAME:-CI upload: $(basename "$UPLOAD_PATH")}"
INTEGRATION_PROVIDER="${SCANFORGE_INTEGRATION_PROVIDER:-}"
REPOSITORY_URL="${SCANFORGE_REPOSITORY_URL:-${CI_PROJECT_URL:-}}"
BRANCH_NAME="${SCANFORGE_BRANCH:-${CI_COMMIT_REF_NAME:-${GITHUB_REF_NAME:-}}}"
COMMIT_SHA="${SCANFORGE_COMMIT_SHA:-${CI_COMMIT_SHA:-${GITHUB_SHA:-}}}"
PIPELINE_URL="${SCANFORGE_PIPELINE_URL:-${CI_PIPELINE_URL:-${GITHUB_SERVER_URL:-}}}"
MERGE_REQUEST="${SCANFORGE_MERGE_REQUEST:-${CI_MERGE_REQUEST_IID:-${GITHUB_REF:-}}}"
RETEST_SCOPE="${SCANFORGE_RETEST_SCOPE:-full_project}"

printf 'Uploading %s to %s\n' "$UPLOAD_PATH" "$SCANFORGE_URL" >&2

if command -v curl >/dev/null 2>&1; then
  curl --fail --silent --show-error \
    -X POST "$SCANFORGE_URL/api/jobs/upload" \
    -H 'Accept: application/json' \
    -F "name=$JOB_NAME" \
    -F "mode=$MODE" \
    -F "preset=$PRESET" \
    -F "retest_scope=$RETEST_SCOPE" \
    -F "integration_provider=$INTEGRATION_PROVIDER" \
    -F "repository_url=$REPOSITORY_URL" \
    -F "branch=$BRANCH_NAME" \
    -F "commit_sha=$COMMIT_SHA" \
    -F "pipeline_url=$PIPELINE_URL" \
    -F "merge_request=$MERGE_REQUEST" \
    -F "upload=@$UPLOAD_PATH"
  exit 0
fi

python3 - "$SCANFORGE_URL" "$UPLOAD_PATH" "$JOB_NAME" "$MODE" "$PRESET" "$RETEST_SCOPE" \
  "$INTEGRATION_PROVIDER" "$REPOSITORY_URL" "$BRANCH_NAME" "$COMMIT_SHA" "$PIPELINE_URL" "$MERGE_REQUEST" <<'PY'
import json
import mimetypes
import os
import sys
import uuid
from urllib.request import Request, urlopen


def multipart_request(url: str, fields: dict[str, str], file_path: str) -> str:
    boundary = f"scanforge-{uuid.uuid4().hex}"
    filename = os.path.basename(file_path)
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    chunks: list[bytes] = []

    for key, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode(),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )

    with open(file_path, "rb") as handle:
        file_content = handle.read()

    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="upload"; filename="{filename}"\r\n'.encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            file_content,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    body = b"".join(chunks)
    request = Request(
        f"{url.rstrip('/')}/api/jobs/upload",
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urlopen(request, timeout=120) as response:
        return response.read().decode("utf-8")


response = multipart_request(
    sys.argv[1],
    {
        "name": sys.argv[3],
        "mode": sys.argv[4],
        "preset": sys.argv[5],
        "retest_scope": sys.argv[6],
        "integration_provider": sys.argv[7],
        "repository_url": sys.argv[8],
        "branch": sys.argv[9],
        "commit_sha": sys.argv[10],
        "pipeline_url": sys.argv[11],
        "merge_request": sys.argv[12],
    },
    sys.argv[2],
)
print(response)
PY
