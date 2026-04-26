from __future__ import annotations

import os
from pathlib import Path

from .config import RUNTIME_LOG_TAIL_LINES, SCANFORGE_LOG_DIR


LOG_FILES = {
    "web": "web.log",
    "worker": "worker.log",
    "launcher": "desktop-launch.log",
}


def _log_dir() -> Path:
    return Path(os.environ.get("SCANFORGE_LOG_DIR", str(SCANFORGE_LOG_DIR)))


def _tail_lines(path: Path, line_count: int) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    byte_window = max(64 * 1024, line_count * 512)
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            file_size = handle.tell()
            handle.seek(max(0, file_size - byte_window))
            payload = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = payload.splitlines()
    return lines[-line_count:]


def runtime_log_status(*, line_count: int = RUNTIME_LOG_TAIL_LINES) -> dict[str, object]:
    log_dir = _log_dir()
    logs = []
    for key, filename in LOG_FILES.items():
        path = log_dir / filename
        logs.append(
            {
                "key": key,
                "label": key.title(),
                "path": str(path),
                "exists": path.exists(),
                "lines": _tail_lines(path, line_count),
            }
        )
    return {
        "log_dir": str(log_dir),
        "tail_lines": line_count,
        "logs": logs,
    }
