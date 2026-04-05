from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("QA_PORTAL_DATA_DIR", ROOT_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOBS_DIR = DATA_DIR / "jobs"
KNOWLEDGE_BASE_DIR = DATA_DIR / "knowledge_base"
KNOWLEDGE_BASE_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw"
KNOWLEDGE_BASE_INDEX_DIR = KNOWLEDGE_BASE_DIR / "indexes"
TEMPLATES_DIR = ROOT_DIR / "qa_portal" / "templates"
STATIC_DIR = ROOT_DIR / "qa_portal" / "static"

MAX_TEXT_FILE_SIZE = 2 * 1024 * 1024


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def get_ai_settings() -> dict[str, str | int | bool]:
    return {
        "enabled": env_bool("AI_ANALYZER_ENABLED", False),
        "url": os.environ.get("AI_ANALYZER_URL", "").strip(),
        "model": os.environ.get("AI_ANALYZER_MODEL", "").strip(),
        "api_key": os.environ.get("AI_ANALYZER_API_KEY", "").strip(),
        "timeout_seconds": env_int("AI_ANALYZER_TIMEOUT_SECONDS", 30),
        "provider": os.environ.get("AI_ANALYZER_PROVIDER", "openai-compatible").strip() or "openai-compatible",
    }


MAX_ARCHIVE_FILE_COUNT = env_int("QA_PORTAL_MAX_ARCHIVE_FILE_COUNT", 5000)
MAX_ARCHIVE_TOTAL_BYTES = env_int("QA_PORTAL_MAX_ARCHIVE_TOTAL_BYTES", 256 * 1024 * 1024)
KEEP_WORKSPACE = env_bool("QA_PORTAL_KEEP_WORKSPACE", False)
KEEP_UPLOADS = env_bool("QA_PORTAL_KEEP_UPLOADS", True)
AUTOSTART_WORKER = env_bool("QA_PORTAL_AUTOSTART_WORKER", True)
WORKER_POLL_SECONDS = env_int("QA_PORTAL_WORKER_POLL_SECONDS", 3)
KB_AUTOSYNC = env_bool("QA_PORTAL_KB_AUTOSYNC", False)
KB_WEEKLY_SYNC = env_bool("QA_PORTAL_KB_WEEKLY_SYNC", False)
KB_WEEKLY_SYNC_DAY = max(0, min(env_int("QA_PORTAL_KB_WEEKLY_SYNC_DAY", 0), 6))
KB_WEEKLY_SYNC_HOUR = max(0, min(env_int("QA_PORTAL_KB_WEEKLY_SYNC_HOUR", 2), 23))
KB_WEEKLY_SYNC_MINUTE = max(0, min(env_int("QA_PORTAL_KB_WEEKLY_SYNC_MINUTE", 0), 59))
KB_SYNC_TIMEOUT_SECONDS = env_int("QA_PORTAL_KB_SYNC_TIMEOUT_SECONDS", 120)
KB_STALE_AFTER_SECONDS = env_int("QA_PORTAL_KB_STALE_AFTER_SECONDS", 24 * 60 * 60)
KB_NVD_YEARLY_MIRROR = env_bool("QA_PORTAL_KB_NVD_YEARLY_MIRROR", True)
KB_NVD_YEAR_START = max(2002, env_int("QA_PORTAL_KB_NVD_YEAR_START", 2002))
KB_NVD_YEAR_END = max(KB_NVD_YEAR_START, env_int("QA_PORTAL_KB_NVD_YEAR_END", datetime.now(timezone.utc).year))
RESOURCE_TARGET_UTILIZATION_PERCENT = max(50, min(env_int("QA_PORTAL_RESOURCE_TARGET_UTILIZATION_PERCENT", 90), 95))
WORKER_PROCESSES = os.environ.get("QA_PORTAL_WORKER_PROCESSES", "auto").strip() or "auto"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
JOBS_DIR.mkdir(parents=True, exist_ok=True)
KNOWLEDGE_BASE_RAW_DIR.mkdir(parents=True, exist_ok=True)
KNOWLEDGE_BASE_INDEX_DIR.mkdir(parents=True, exist_ok=True)
