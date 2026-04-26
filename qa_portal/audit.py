from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DATA_DIR


AUDIT_LOG_PATH = DATA_DIR / "audit" / "events.jsonl"
SECRET_KEY_PARTS = (
    "api_key",
    "authorization",
    "auth_cookie",
    "auth_token",
    "cookie",
    "password",
    "secret",
    "token",
)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_secret_key(key: object) -> bool:
    normalized = str(key).strip().casefold()
    return any(part in normalized for part in SECRET_KEY_PARTS)


def sanitize_audit_details(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if _is_secret_key(key):
                sanitized[str(key)] = "<redacted>" if str(item).strip() else ""
            else:
                sanitized[str(key)] = sanitize_audit_details(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_audit_details(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def audit_actor_from_request(request: object | None) -> dict[str, str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    client = getattr(request, "client", None)
    return {
        "username": str(getattr(auth, "username", "anonymous") or "anonymous"),
        "role": str(getattr(auth, "role", "unknown") or "unknown"),
        "client": str(getattr(client, "host", "") or ""),
    }


def request_audit_details(request: object | None) -> dict[str, str]:
    if request is None:
        return {}
    url = getattr(request, "url", None)
    return {
        "method": str(getattr(request, "method", "") or ""),
        "path": str(getattr(url, "path", "") or ""),
    }


def append_audit_event(
    action: str,
    *,
    outcome: str = "success",
    actor: dict[str, str] | None = None,
    resource_type: str = "",
    resource_id: str = "",
    details: dict[str, Any] | None = None,
    path: Path = AUDIT_LOG_PATH,
) -> dict[str, Any]:
    event = {
        "timestamp": utc_timestamp(),
        "action": action,
        "outcome": outcome,
        "actor": sanitize_audit_details(actor or {"username": "system", "role": "system", "client": ""}),
        "resource": {
            "type": resource_type,
            "id": resource_id,
        },
        "details": sanitize_audit_details(details or {}),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError:
        event["write_error"] = True
    return event


def list_audit_events(*, limit: int = 100, path: Path = AUDIT_LOG_PATH) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in reversed(lines):
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
        if len(events) >= limit:
            break
    events.reverse()
    return events


def audit_status(*, limit: int = 100, path: Path = AUDIT_LOG_PATH) -> dict[str, Any]:
    events = list_audit_events(limit=limit, path=path)
    return {
        "path": str(path),
        "exists": path.exists(),
        "events": events,
        "event_count": len(events),
    }
