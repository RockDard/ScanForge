from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any


# Базовые директории ScanForge и рабочие каталоги портала.
ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("QA_PORTAL_DATA_DIR", ROOT_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOBS_DIR = DATA_DIR / "jobs"
KNOWLEDGE_BASE_DIR = DATA_DIR / "knowledge_base"
KNOWLEDGE_BASE_RAW_DIR = KNOWLEDGE_BASE_DIR / "raw"
KNOWLEDGE_BASE_INDEX_DIR = KNOWLEDGE_BASE_DIR / "indexes"
LOCAL_MODEL_DIR = DATA_DIR / "models"
SETTINGS_DIR = DATA_DIR / "settings"
AI_SETTINGS_PATH = SETTINGS_DIR / "ai_backend.json"
INTEGRATIONS_SETTINGS_PATH = SETTINGS_DIR / "integrations.json"
FINDING_LIFECYCLE_DIR = SETTINGS_DIR / "finding_lifecycle"
DEPENDENCY_SUPPRESSIONS_PATH = SETTINGS_DIR / "dependency_suppressions.json"
RELEASE_GATE_POLICY_PATH = SETTINGS_DIR / "release_gate_policy.json"
INTEGRATION_EVENTS_DIR = DATA_DIR / "integration_events"
TOOL_INSTALL_JOBS_DIR = DATA_DIR / "tool_install_jobs"
TEMPLATES_DIR = ROOT_DIR / "qa_portal" / "templates"
STATIC_DIR = ROOT_DIR / "qa_portal" / "static"

MAX_TEXT_FILE_SIZE = 2 * 1024 * 1024


# Небольшие помощники для чтения конфигурации из переменных окружения.
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


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_ai_settings_file() -> dict[str, Any]:
    if not AI_SETTINGS_PATH.exists():
        return {}
    try:
        payload = json.loads(AI_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_ai_settings_file(payload: dict[str, Any]) -> None:
    AI_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(AI_SETTINGS_PATH.parent),
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(AI_SETTINGS_PATH)


def get_ai_settings() -> dict[str, str | int | bool]:
    env_settings = {
        "enabled": env_bool("AI_ANALYZER_ENABLED", False),
        "url": os.environ.get("AI_ANALYZER_URL", "").strip(),
        "model": os.environ.get("AI_ANALYZER_MODEL", "").strip(),
        "api_key": os.environ.get("AI_ANALYZER_API_KEY", "").strip(),
        "timeout_seconds": env_int("AI_ANALYZER_TIMEOUT_SECONDS", 30),
        "provider": os.environ.get("AI_ANALYZER_PROVIDER", "openai-compatible").strip() or "openai-compatible",
        "routing_mode": os.environ.get("AI_ANALYZER_ROUTING_MODE", "auto").strip() or "auto",
        "preferred_local_model": os.environ.get("AI_ANALYZER_LOCAL_MODEL", "").strip(),
    }
    file_settings = _load_ai_settings_file()
    merged = dict(env_settings)
    if file_settings:
        merged.update(
            {
                "enabled": _coerce_bool(file_settings.get("enabled"), bool(env_settings["enabled"])),
                "url": str(file_settings.get("url", env_settings["url"])).strip(),
                "model": str(file_settings.get("model", env_settings["model"])).strip(),
                "api_key": str(file_settings.get("api_key", env_settings["api_key"])).strip(),
                "timeout_seconds": max(5, min(_coerce_int(file_settings.get("timeout_seconds"), int(env_settings["timeout_seconds"])), 300)),
                "provider": str(file_settings.get("provider", env_settings["provider"])).strip() or "openai-compatible",
                "routing_mode": str(file_settings.get("routing_mode", env_settings["routing_mode"])).strip() or "auto",
                "preferred_local_model": str(file_settings.get("preferred_local_model", env_settings["preferred_local_model"])).strip(),
            }
        )
    merged["source"] = "file" if file_settings else "environment"
    merged["api_key_configured"] = bool(merged["api_key"])
    return merged


# Сохраняем настройки AI в локальный JSON-файл, чтобы ими можно было управлять из веб-интерфейса.
def save_ai_settings(payload: dict[str, Any]) -> dict[str, str | int | bool]:
    current = get_ai_settings()
    stored = {
        "enabled": _coerce_bool(payload.get("enabled"), bool(current["enabled"])),
        "url": str(payload.get("url", current["url"])).strip(),
        "model": str(payload.get("model", current["model"])).strip(),
        "api_key": (
            str(payload["api_key"]).strip()
            if "api_key" in payload and str(payload["api_key"]).strip()
            else str(current["api_key"]).strip()
        ),
        "timeout_seconds": max(5, min(_coerce_int(payload.get("timeout_seconds"), int(current["timeout_seconds"])), 300)),
        "provider": str(payload.get("provider", current["provider"])).strip() or "openai-compatible",
        "routing_mode": str(payload.get("routing_mode", current["routing_mode"])).strip() or "auto",
        "preferred_local_model": str(payload.get("preferred_local_model", current["preferred_local_model"])).strip(),
    }
    _write_ai_settings_file(stored)
    return get_ai_settings()


# Пределы загрузки, worker-контур и расписание фоновых задач.
MAX_UPLOAD_FILES = max(1, env_int("QA_PORTAL_MAX_UPLOAD_FILES", 20))
MAX_UPLOAD_BYTES = max(1, env_int("QA_PORTAL_MAX_UPLOAD_BYTES", 512 * 1024 * 1024))
MAX_ARCHIVE_FILE_COUNT = env_int("QA_PORTAL_MAX_ARCHIVE_FILE_COUNT", 5000)
MAX_ARCHIVE_TOTAL_BYTES = env_int("QA_PORTAL_MAX_ARCHIVE_TOTAL_BYTES", 256 * 1024 * 1024)
KEEP_WORKSPACE = env_bool("QA_PORTAL_KEEP_WORKSPACE", False)
KEEP_UPLOADS = env_bool("QA_PORTAL_KEEP_UPLOADS", True)
AUTOSTART_WORKER = env_bool("QA_PORTAL_AUTOSTART_WORKER", True)
WORKER_POLL_SECONDS = env_int("QA_PORTAL_WORKER_POLL_SECONDS", 3)
STALE_RUNNING_SECONDS = max(60, env_int("QA_PORTAL_STALE_RUNNING_SECONDS", 6 * 60 * 60))
SCANFORGE_LOG_DIR = Path(os.environ.get("SCANFORGE_LOG_DIR", "/var/log/scanforge"))
RUNTIME_LOG_TAIL_LINES = max(20, min(env_int("QA_PORTAL_RUNTIME_LOG_TAIL_LINES", 120), 500))
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

# Готовим рабочие каталоги до старта приложения.
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
JOBS_DIR.mkdir(parents=True, exist_ok=True)
KNOWLEDGE_BASE_RAW_DIR.mkdir(parents=True, exist_ok=True)
KNOWLEDGE_BASE_INDEX_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_MODEL_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
FINDING_LIFECYCLE_DIR.mkdir(parents=True, exist_ok=True)
INTEGRATION_EVENTS_DIR.mkdir(parents=True, exist_ok=True)
TOOL_INSTALL_JOBS_DIR.mkdir(parents=True, exist_ok=True)
