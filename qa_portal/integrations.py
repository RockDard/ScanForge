from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import INTEGRATION_EVENTS_DIR, INTEGRATIONS_SETTINGS_PATH


SUPPORTED_INTEGRATIONS = (
    "gitlab",
    "github",
    "jenkins",
    "teamcity",
    "azure_devops",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_settings() -> dict[str, Any]:
    providers = {}
    for provider in SUPPORTED_INTEGRATIONS:
        providers[provider] = {
            "enabled": False,
            "base_url": "",
            "token": "",
            "webhook_secret": "",
            "default_mode": "full_scan",
            "default_preset": "balanced",
        }
    return {
        "updated_at": None,
        "providers": providers,
    }


def _load_settings() -> dict[str, Any]:
    if not INTEGRATIONS_SETTINGS_PATH.exists():
        return _default_settings()
    try:
        payload = json.loads(INTEGRATIONS_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _default_settings()
    if not isinstance(payload, dict):
        return _default_settings()
    settings = _default_settings()
    providers = payload.get("providers", {})
    if isinstance(providers, dict):
        for provider in SUPPORTED_INTEGRATIONS:
            current = settings["providers"][provider]
            overrides = providers.get(provider, {})
            if not isinstance(overrides, dict):
                continue
            current.update(
                {
                    "enabled": bool(overrides.get("enabled", current["enabled"])),
                    "base_url": str(overrides.get("base_url", current["base_url"])).strip(),
                    "token": str(overrides.get("token", current["token"])).strip(),
                    "webhook_secret": str(overrides.get("webhook_secret", current["webhook_secret"])).strip(),
                    "default_mode": str(overrides.get("default_mode", current["default_mode"])).strip() or "full_scan",
                    "default_preset": str(overrides.get("default_preset", current["default_preset"])).strip() or "balanced",
                }
            )
    settings["updated_at"] = payload.get("updated_at")
    return settings


def _save_settings(payload: dict[str, Any]) -> None:
    INTEGRATIONS_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(INTEGRATIONS_SETTINGS_PATH.parent),
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(INTEGRATIONS_SETTINGS_PATH)


# Возвращаем обзор интеграций без секретов, но с webhook-адресами и шаблонами запуска.
def integration_status(base_url: str) -> dict[str, Any]:
    settings = _load_settings()
    providers: list[dict[str, Any]] = []
    for provider in SUPPORTED_INTEGRATIONS:
        config = settings["providers"][provider]
        providers.append(
            {
                "key": provider,
                "enabled": bool(config["enabled"]),
                "base_url": str(config["base_url"]),
                "token_configured": bool(config["token"]),
                "webhook_secret_configured": bool(config["webhook_secret"]),
                "default_mode": str(config["default_mode"]),
                "default_preset": str(config["default_preset"]),
                "webhook_url": f"{base_url.rstrip('/')}/api/integrations/webhooks/{provider}",
            }
        )
    events = recent_integration_events()
    return {
        "updated_at": settings.get("updated_at"),
        "enabled_count": sum(1 for item in providers if item["enabled"]),
        "providers": providers,
        "recent_events": events,
        "examples": build_ci_examples(base_url),
    }


def save_integration_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings = _load_settings()
    providers_payload = payload.get("providers", {})
    if isinstance(providers_payload, dict):
        for provider in SUPPORTED_INTEGRATIONS:
            provider_payload = providers_payload.get(provider)
            if not isinstance(provider_payload, dict):
                continue
            settings["providers"][provider].update(
                {
                    "enabled": bool(provider_payload.get("enabled", settings["providers"][provider]["enabled"])),
                    "base_url": str(provider_payload.get("base_url", settings["providers"][provider]["base_url"])).strip(),
                    "token": str(provider_payload.get("token", settings["providers"][provider]["token"])).strip(),
                    "webhook_secret": str(provider_payload.get("webhook_secret", settings["providers"][provider]["webhook_secret"])).strip(),
                    "default_mode": str(provider_payload.get("default_mode", settings["providers"][provider]["default_mode"])).strip() or "full_scan",
                    "default_preset": str(provider_payload.get("default_preset", settings["providers"][provider]["default_preset"])).strip() or "balanced",
                }
            )
    settings["updated_at"] = _utc_now()
    _save_settings(settings)
    return settings


def record_integration_event(provider: str, headers: dict[str, str], payload: Any) -> dict[str, Any]:
    if provider not in SUPPORTED_INTEGRATIONS:
        raise ValueError(f"Unsupported integration provider: {provider}")
    INTEGRATION_EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    event_id = f"{_utc_now().replace(':', '-').replace('.', '-')}_{provider}"
    event_path = INTEGRATION_EVENTS_DIR / f"{event_id}.json"
    event_payload = {
        "provider": provider,
        "received_at": _utc_now(),
        "headers": headers,
        "payload": payload,
    }
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(INTEGRATION_EVENTS_DIR),
    ) as handle:
        json.dump(event_payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(event_path)
    return {
        "ok": True,
        "provider": provider,
        "event_id": event_path.stem,
        "path": str(event_path),
    }


def recent_integration_events(limit: int = 8) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(INTEGRATION_EVENTS_DIR.glob("*.json"), reverse=True)[:limit]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        items.append(
            {
                "id": path.stem,
                "provider": payload.get("provider", "unknown"),
                "received_at": payload.get("received_at"),
            }
        )
    return items


def build_ci_examples(base_url: str) -> dict[str, str]:
    normalized = base_url.rstrip("/")
    upload_url = f"{normalized}/api/jobs/upload"
    return {
        "curl": (
            f"curl -X POST {upload_url} "
            "-F mode=full_scan -F preset=balanced "
            "-F name='CI upload' -F upload=@project.zip"
        ),
        "script": "./scripts/scanforge-ci-agent.sh http://127.0.0.1:8000 ./project.zip",
        "gitlab": (
            "scanforge:\n"
            "  script:\n"
            "    - ./scripts/scanforge-ci-agent.sh "
            f"{normalized} \"$CI_PROJECT_DIR/artifacts/project.zip\""
        ),
    }
