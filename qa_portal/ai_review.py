from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover
    class _HttpxFallbackModule:
        Client = None
        HTTPError = Exception

    httpx = _HttpxFallbackModule()  # type: ignore[assignment]

from .config import LOCAL_MODEL_DIR, get_ai_settings


USER_AGENT = "ScanForge/0.2"
DEFAULT_ASSISTANT_MODEL = {
    "id": "scanforge-local-analyst",
    "label": "ScanForge Local Analyst",
    "description": "Встроенный детерминированный помощник для сводки, triage и release-рекомендаций.",
    "role": "fallback-review",
    "default": True,
    "builtin": True,
}
LOCAL_MODEL_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "id": "qwen2.5-coder-3b-instruct",
        "label": "Qwen2.5 Coder 3B Instruct GGUF",
        "description": "Подходит для code review, статанализа и пояснения причин падений тестов.",
        "role": "code-and-test-review",
        "download_url": (
            "https://huggingface.co/bartowski/Qwen2.5-Coder-3B-Instruct-GGUF/resolve/main/"
            "Qwen2.5-Coder-3B-Instruct-Q4_K_M.gguf"
        ),
        "filename": "Qwen2.5-Coder-3B-Instruct-Q4_K_M.gguf",
        "size_hint_gb": 2.1,
        "default": True,
        "builtin": False,
    },
    {
        "id": "llama-3.2-3b-instruct",
        "label": "Llama 3.2 3B Instruct GGUF",
        "description": "Универсальный помощник для коротких сводок по качеству, безопасности и функциональности.",
        "role": "general-review",
        "download_url": (
            "https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/"
            "Llama-3.2-3B-Instruct-Q4_K_M.gguf"
        ),
        "filename": "Llama-3.2-3B-Instruct-Q4_K_M.gguf",
        "size_hint_gb": 2.0,
        "default": False,
        "builtin": False,
    },
    {
        "id": "deepseek-r1-distill-qwen-7b",
        "label": "DeepSeek R1 Distill Qwen 7B GGUF",
        "description": "Полезен для более глубокого reasoning по регрессиям и сложным release-решениям.",
        "role": "deep-investigation",
        "download_url": (
            "https://huggingface.co/bartowski/DeepSeek-R1-Distill-Qwen-7B-GGUF/resolve/main/"
            "DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf"
        ),
        "filename": "DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf",
        "size_hint_gb": 4.7,
        "default": False,
        "builtin": False,
    },
)
MODEL_BY_ID = {item["id"]: item for item in LOCAL_MODEL_CATALOG}
_MODEL_DOWNLOAD_LOCK = threading.Lock()
_MODEL_DOWNLOAD_STATE: dict[str, dict[str, Any]] = {}
_MODEL_DOWNLOAD_THREADS: dict[str, threading.Thread] = {}
AI_PLAYBOOKS: tuple[dict[str, str], ...] = (
    {
        "id": "triage",
        "title": "Risk triage and release decision",
        "used_when": "A scan reaches the reporting stage and the operator needs a fast decision snapshot.",
        "output": "Overview, blockers, quick wins, and release readiness guidance.",
    },
    {
        "id": "root-cause",
        "title": "Root-cause clustering",
        "used_when": "Several findings point to the same architectural or coding pattern problem.",
        "output": "Grouped causes, likely defect families, and remediation direction.",
    },
    {
        "id": "test-design",
        "title": "Regression and test design",
        "used_when": "A project needs follow-up tests after security, quality, or functionality findings.",
        "output": "Suggested regression tests, sanitizer follow-ups, and candidate fuzz targets.",
    },
    {
        "id": "dependency-review",
        "title": "Dependency and supply-chain review",
        "used_when": "Dependency manifests were detected and the report needs supply-chain context.",
        "output": "Dependency notes, pinning concerns, and ecosystem-specific review prompts.",
    },
    {
        "id": "crash-troubleshooting",
        "title": "Crash and sanitizer troubleshooting",
        "used_when": "Dynamic analysis, fuzzing or VM/runtime tracing produced crashes, traces or sanitizer noise.",
        "output": "Crash clusters, runtime explanations, patch candidates and replay hints.",
    },
)
PLAYBOOK_BY_ID = {item["id"]: item for item in AI_PLAYBOOKS}
AI_PROVIDER_OPTIONS: tuple[dict[str, str], ...] = (
    {
        "id": "openai-compatible",
        "label": "OpenAI-compatible",
        "description": "Подходит для OpenAI-compatible chat/completions endpoint.",
    },
    {
        "id": "ollama-openai",
        "label": "Ollama OpenAI API",
        "description": "Локальный OpenAI-compatible endpoint через Ollama.",
    },
    {
        "id": "lm-studio-openai",
        "label": "LM Studio OpenAI API",
        "description": "Локальный OpenAI-compatible endpoint через LM Studio.",
    },
)
AI_ROUTING_OPTIONS: tuple[dict[str, str], ...] = (
    {
        "id": "auto",
        "label": "Auto",
        "description": "Приоритет remote AI, затем локальная GGUF-модель, затем детерминированный fallback.",
    },
    {
        "id": "remote-first",
        "label": "Remote first",
        "description": "Сначала использовать удаленный AI-бэкенд, а локальную модель брать только как резерв.",
    },
    {
        "id": "local-first",
        "label": "Local first",
        "description": "Сначала использовать локальную GGUF-модель, а удаленный AI брать только как резерв.",
    },
    {
        "id": "fallback-only",
        "label": "Fallback only",
        "description": "Не использовать сетевые или локальные LLM и строить только встроенный детерминированный обзор.",
    },
)
_VALID_ROUTING_MODES = {item["id"] for item in AI_ROUTING_OPTIONS}
_PLAYBOOK_ROLE_PRIORITY: dict[str, tuple[str, ...]] = {
    "triage": ("general-review", "code-and-test-review", "deep-investigation"),
    "root-cause": ("deep-investigation", "code-and-test-review", "general-review"),
    "test-design": ("code-and-test-review", "general-review", "deep-investigation"),
    "dependency-review": ("code-and-test-review", "deep-investigation", "general-review"),
    "crash-troubleshooting": ("deep-investigation", "code-and-test-review", "general-review"),
}


def _normalize_routing_mode(value: Any) -> str:
    normalized = str(value or "auto").strip()
    return normalized if normalized in _VALID_ROUTING_MODES else "auto"


def _playbook_titles(playbook_ids: list[str]) -> list[str]:
    return [PLAYBOOK_BY_ID[item]["title"] for item in playbook_ids if item in PLAYBOOK_BY_ID]


# Активируем playbook-сценарии по фактическим данным отчета, а не по статическому каталогу.
def select_active_playbooks(report_data: dict[str, Any]) -> list[str]:
    summary = report_data.get("summary") or {}
    dependencies = report_data.get("dependencies") or {}
    dependency_diff = report_data.get("dependency_diff") or {}
    lifecycle = report_data.get("finding_lifecycle") or {}
    dynamic = report_data.get("dynamic_analysis") or {}
    service_runtime = report_data.get("service_runtime") or {}
    vm_runtime = report_data.get("vm_runtime") or {}
    finding_count = int(summary.get("total_findings", 0) or 0)

    playbooks: list[str] = ["triage"]
    if (
        finding_count >= 3
        or int(lifecycle.get("persisting_count", 0) or 0) > 0
        or len(summary.get("category_breakdown") or []) > 1
    ):
        playbooks.append("root-cause")
    if finding_count > 0 or bool(summary.get("next_actions")) or bool(dynamic):
        playbooks.append("test-design")
    if int(dependencies.get("component_count", 0) or 0) > 0 or bool(dependency_diff):
        playbooks.append("dependency-review")
    if (
        bool(dynamic.get("sanitizer_tests_ran"))
        or bool(dynamic.get("report"))
        or bool(service_runtime.get("verification_results"))
        or int(service_runtime.get("source_correlated_paths", 0) or 0) > 0
        or bool(vm_runtime.get("process_trace_collected"))
        or bool(vm_runtime.get("crash_replay_script"))
    ):
        playbooks.append("crash-troubleshooting")
    return playbooks


def _remote_backend_configured(settings: dict[str, Any]) -> bool:
    return bool(settings.get("enabled") and settings.get("url") and settings.get("model"))


def _model_path(model_spec: dict[str, Any]) -> Path | None:
    filename = model_spec.get("filename")
    if not filename:
        return None
    return LOCAL_MODEL_DIR / model_spec["id"] / str(filename)


def _detect_local_runner() -> str | None:
    return shutil.which("llama-cli")


def _download_state(model_id: str) -> dict[str, Any]:
    with _MODEL_DOWNLOAD_LOCK:
        payload = dict(_MODEL_DOWNLOAD_STATE.get(model_id, {}))
        thread = _MODEL_DOWNLOAD_THREADS.get(model_id)
    payload["running"] = bool(payload.get("running")) or bool(thread and thread.is_alive())
    return payload


# Возвращаем фабрику httpx-клиента с явным nullable-типом, чтобы type-checker корректно сузил ветку fallback.
def _httpx_client_factory() -> Callable[..., Any] | None:
    client_factory = getattr(httpx, "Client", None)
    return client_factory if callable(client_factory) else None


# Возвращаем каталог моделей уже в виде, удобном для UI.
def list_local_models() -> list[dict[str, Any]]:
    runner_path = _detect_local_runner()
    items: list[dict[str, Any]] = []
    for model_spec in LOCAL_MODEL_CATALOG:
        path = _model_path(model_spec)
        download_state = _download_state(model_spec["id"])
        installed = bool(path and path.exists())
        items.append(
            {
                **model_spec,
                "path": str(path) if path else "",
                "installed": installed,
                "runner_ready": bool(installed and runner_path),
                "download_state": download_state,
            }
        )
    return items


def _model_score_for_playbooks(model: dict[str, Any], playbook_ids: list[str]) -> int:
    score = 0
    role = str(model.get("role", "") or "")
    for playbook_id in playbook_ids:
        priorities = _PLAYBOOK_ROLE_PRIORITY.get(playbook_id, ())
        if role in priorities:
            score += max(1, len(priorities) - priorities.index(role))
    if model.get("default"):
        score += 1
    return score


# Подбираем локальную модель под сценарий отчета и настройки оператора.
def preferred_local_model(
    report_data: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    runner_path = _detect_local_runner()
    if not runner_path:
        return None, "llama.cpp runner is not installed."

    current_settings = settings or get_ai_settings()
    models = list_local_models()
    installed = [item for item in models if item.get("installed")]
    if not installed:
        return None, "No downloaded local GGUF models are available."

    preferred_id = str(current_settings.get("preferred_local_model", "") or "").strip()
    if preferred_id and preferred_id != "auto":
        selected = next((item for item in installed if item.get("id") == preferred_id), None)
        if selected is not None:
            return selected, f"Operator-selected local model {selected['label']} is pinned in AI settings."

    playbook_ids = select_active_playbooks(report_data or {}) if report_data else ["triage"]
    installed.sort(
        key=lambda item: (
            -_model_score_for_playbooks(item, playbook_ids),
            not item.get("default", False),
            item["label"],
        )
    )
    selected = installed[0]
    playbook_titles = ", ".join(_playbook_titles(playbook_ids))
    return selected, f"Selected {selected['label']} for playbooks: {playbook_titles or 'triage'}."


def _resolved_backend_mode(
    *,
    routing_mode: str,
    remote_configured: bool,
    local_model_available: bool,
) -> str:
    if routing_mode == "fallback-only":
        return "local-fallback"
    if routing_mode == "local-first":
        if local_model_available:
            return "local-llm"
        if remote_configured:
            return "remote-ai"
        return "local-fallback"
    if routing_mode == "remote-first":
        if remote_configured:
            return "remote-ai"
        if local_model_available:
            return "local-llm"
        return "local-fallback"
    if remote_configured:
        return "remote-ai"
    if local_model_available:
        return "local-llm"
    return "local-fallback"


def _backend_routing_reason(
    *,
    routing_mode: str,
    active_mode: str,
    remote_configured: bool,
    local_reason: str,
) -> str:
    if routing_mode == "fallback-only":
        return "Routing mode forces deterministic fallback review only."
    if active_mode == "remote-ai" and remote_configured:
        if routing_mode == "local-first":
            return "Local-first routing fell back to the remote backend because no suitable local model is available."
        return "Remote backend is configured and selected by the current routing policy."
    if active_mode == "local-llm":
        return local_reason or "A local GGUF model is selected by the current routing policy."
    return "No remote or local LLM backend is ready, so the deterministic fallback review is used."


def _update_download_state(model_id: str, **changes: Any) -> dict[str, Any]:
    with _MODEL_DOWNLOAD_LOCK:
        current = dict(_MODEL_DOWNLOAD_STATE.get(model_id, {}))
        current.update(changes)
        _MODEL_DOWNLOAD_STATE[model_id] = current
        return dict(current)


def _download_model_file(model_spec: dict[str, Any]) -> Path:
    target_path = _model_path(model_spec)
    if target_path is None:
        raise RuntimeError("Model has no target file.")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    request = Request(str(model_spec["download_url"]), headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=60) as response:
        total_bytes_raw = response.headers.get("Content-Length", "")
        total_bytes = int(total_bytes_raw) if str(total_bytes_raw).isdigit() else 0
        downloaded_bytes = 0
        _update_download_state(
            model_spec["id"],
            downloaded_bytes=0,
            total_bytes=total_bytes,
            progress_percent=0,
            updated_at=time.time(),
        )
        with tempfile.NamedTemporaryFile(delete=False, dir=str(target_path.parent)) as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                downloaded_bytes += len(chunk)
                progress_percent = int((downloaded_bytes / total_bytes) * 100) if total_bytes else 0
                _update_download_state(
                    model_spec["id"],
                    downloaded_bytes=downloaded_bytes,
                    total_bytes=total_bytes,
                    progress_percent=max(0, min(progress_percent, 100)),
                    updated_at=time.time(),
                )
            temp_name = handle.name
    Path(temp_name).replace(target_path)
    final_total = total_bytes or downloaded_bytes
    _update_download_state(
        model_spec["id"],
        downloaded_bytes=downloaded_bytes,
        total_bytes=final_total,
        progress_percent=100 if final_total else 0,
        updated_at=time.time(),
    )
    return target_path


def _model_download_worker(model_id: str) -> None:
    model_spec = MODEL_BY_ID[model_id]
    try:
        _download_model_file(model_spec)
        _update_download_state(model_id, running=False, finished=True, error="", updated_at=time.time())
    except Exception as exc:
        _update_download_state(model_id, running=False, finished=True, error=str(exc), updated_at=time.time())
    finally:
        with _MODEL_DOWNLOAD_LOCK:
            _MODEL_DOWNLOAD_THREADS.pop(model_id, None)


def start_local_model_download(model_id: str) -> dict[str, Any]:
    model_spec = MODEL_BY_ID.get(model_id)
    if model_spec is None:
        return {"started": False, "status": "unknown-model", "message": f"Unknown model: {model_id}"}
    target_path = _model_path(model_spec)
    if target_path and target_path.exists():
        return {"started": False, "status": "already-installed", "message": f"{model_spec['label']} is already installed."}
    state = _download_state(model_id)
    if state.get("running"):
        return {"started": False, "status": "already-running", "message": f"{model_spec['label']} download is already running."}
    thread = threading.Thread(target=_model_download_worker, args=(model_id,), name=f"qa-model-download-{model_id}", daemon=True)
    _update_download_state(
        model_id,
        running=True,
        finished=False,
        error="",
        downloaded_bytes=0,
        total_bytes=0,
        progress_percent=0,
        started_at=time.time(),
        updated_at=time.time(),
    )
    with _MODEL_DOWNLOAD_LOCK:
        _MODEL_DOWNLOAD_THREADS[model_id] = thread
    thread.start()
    return {"started": True, "status": "started", "message": f"{model_spec['label']} download started."}


def ai_backend_status() -> dict[str, Any]:
    settings = get_ai_settings()
    remote_enabled = bool(settings["enabled"])
    remote_configured = _remote_backend_configured(settings)
    local_runner = _detect_local_runner()
    local_model, local_reason = preferred_local_model(settings=settings)
    local_models = list_local_models()
    routing_mode = _normalize_routing_mode(settings.get("routing_mode"))
    active_mode = _resolved_backend_mode(
        routing_mode=routing_mode,
        remote_configured=remote_configured,
        local_model_available=bool(local_model),
    )
    provider = "scanforge-local"
    model_name = DEFAULT_ASSISTANT_MODEL["label"]
    if active_mode == "remote-ai":
        provider = str(settings["provider"])
        model_name = str(settings["model"] or "not set")
    elif active_mode == "local-llm" and local_model:
        provider = "llama.cpp"
        model_name = local_model["label"]
    return {
        "enabled": remote_enabled,
        "configured": remote_configured,
        "provider": provider,
        "model": model_name,
        "endpoint": settings["url"] or "not set",
        "mode": active_mode,
        "default_model": DEFAULT_ASSISTANT_MODEL,
        "local_models": local_models,
        "local_runner": {
            "available": bool(local_runner),
            "path": local_runner or "not installed",
        },
        "downloads_running": sum(1 for item in local_models if item.get("download_state", {}).get("running")),
        "active_local_model": local_model,
        "routing_reason": _backend_routing_reason(
            routing_mode=routing_mode,
            active_mode=active_mode,
            remote_configured=remote_configured,
            local_reason=local_reason,
        ),
        "settings": {
            "enabled": remote_enabled,
            "url": str(settings.get("url", "") or ""),
            "model": str(settings.get("model", "") or ""),
            "provider": str(settings.get("provider", "openai-compatible") or "openai-compatible"),
            "timeout_seconds": int(settings.get("timeout_seconds", 30) or 30),
            "source": str(settings.get("source", "environment") or "environment"),
            "api_key_configured": bool(settings.get("api_key_configured")),
            "routing_mode": routing_mode,
            "preferred_local_model": str(settings.get("preferred_local_model", "") or ""),
        },
        "provider_options": list(AI_PROVIDER_OPTIONS),
        "routing_options": list(AI_ROUTING_OPTIONS),
        "local_model_options": [
            {"id": "auto", "label": "Automatic selection"}
        ] + [{"id": item["id"], "label": item["label"]} for item in LOCAL_MODEL_CATALOG],
        "playbooks": list(AI_PLAYBOOKS),
    }


def _review_backend(report_data: dict[str, Any]) -> dict[str, Any]:
    backend = ai_backend_status()
    settings = get_ai_settings()
    local_model, local_reason = preferred_local_model(report_data=report_data, settings=settings)
    routing_mode = _normalize_routing_mode(settings.get("routing_mode"))
    active_mode = _resolved_backend_mode(
        routing_mode=routing_mode,
        remote_configured=bool(backend.get("configured")),
        local_model_available=bool(local_model),
    )
    provider = "scanforge-local"
    model_name = DEFAULT_ASSISTANT_MODEL["label"]
    if active_mode == "remote-ai":
        provider = str(settings.get("provider", "openai-compatible") or "openai-compatible")
        model_name = str(settings.get("model", "") or "not set")
    elif active_mode == "local-llm" and local_model:
        provider = "llama.cpp"
        model_name = str(local_model.get("label", "Local model"))
    backend.update(
        {
            "mode": active_mode,
            "provider": provider,
            "model": model_name,
            "active_local_model": local_model,
            "selected_playbooks": select_active_playbooks(report_data),
            "routing_reason": _backend_routing_reason(
                routing_mode=routing_mode,
                active_mode=active_mode,
                remote_configured=bool(backend.get("configured")),
                local_reason=local_reason,
            ),
        }
    )
    return backend


def probe_ai_backend() -> dict[str, Any]:
    backend = ai_backend_status()
    settings = get_ai_settings()
    remote_probe = {
        "configured": bool(backend.get("configured")),
        "ok": False,
        "message": "Remote backend is not configured.",
    }
    if backend.get("configured"):
        headers = {"Content-Type": "application/json"}
        if settings.get("api_key"):
            headers["Authorization"] = f"Bearer {settings['api_key']}"
        payload = {
            "model": settings.get("model"),
            "temperature": 0,
            "max_tokens": 1,
            "messages": [
                {
                    "role": "user",
                    "content": "{}",
                }
            ],
        }
        try:
            client_factory = _httpx_client_factory()
            if client_factory is not None:
                with client_factory(timeout=int(settings["timeout_seconds"])) as client:
                    response = client.post(str(settings["url"]), headers=headers, json=payload)
                    response.raise_for_status()
                    body = response.json()
            else:
                request = Request(
                    str(settings["url"]),
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urlopen(request, timeout=int(settings["timeout_seconds"])) as response:
                    body = json.loads(response.read().decode("utf-8"))
            remote_probe = {
                "configured": True,
                "ok": True,
                "message": "Remote backend responded with a valid JSON payload.",
                "response_keys": sorted(body.keys()) if isinstance(body, dict) else [],
            }
        except Exception as exc:
            remote_probe = {
                "configured": True,
                "ok": False,
                "message": f"Remote backend probe failed: {exc}",
            }

    local_model = backend.get("active_local_model")
    local_probe = {
        "runner_available": bool(backend.get("local_runner", {}).get("available")),
        "model_available": bool(local_model),
        "selected_model": str(local_model.get("label", "")) if isinstance(local_model, dict) else "",
        "message": "",
    }
    if local_probe["runner_available"] and local_probe["model_available"]:
        local_probe["message"] = "Local llama.cpp runner and a compatible GGUF model are available."
    elif local_probe["runner_available"]:
        local_probe["message"] = "llama.cpp runner is installed, but no downloaded GGUF model is ready."
    else:
        local_probe["message"] = "llama.cpp runner is not installed on this host."

    return {
        "mode": backend.get("mode"),
        "routing_reason": backend.get("routing_reason", ""),
        "remote": remote_probe,
        "local": local_probe,
        "fallback_available": True,
        "ok": bool(remote_probe.get("ok")) or bool(local_probe.get("model_available")),
        "message": "Probe completed.",
    }


def _release_decision(summary: dict[str, Any]) -> str:
    if summary.get("highest_severity") == "critical":
        return "blocked"
    if summary.get("highest_severity") == "high":
        return "needs-fixes"
    if summary.get("execution_verdict") in {"blocked", "configured-only"}:
        return "needs-build-stabilization"
    if summary.get("total_findings", 0) > 25:
        return "review-before-release"
    return "acceptable-for-internal-testing"


def _fallback_review(report_data: dict[str, Any], backend: dict[str, Any], reason: str = "") -> dict[str, Any]:
    summary = report_data["summary"]
    project = report_data["project"]
    playbook_ids = list(backend.get("selected_playbooks") or select_active_playbooks(report_data))
    high_or_critical = summary["severity_counts"].get("critical", 0) + summary["severity_counts"].get("high", 0)
    languages = project.get("programming_languages", [])
    dependencies = report_data.get("dependencies", {})
    dependency_diff = report_data.get("dependency_diff", {})
    lifecycle = report_data.get("finding_lifecycle", {})
    service_runtime = report_data.get("service_runtime", {})
    dynamic_analysis = report_data.get("dynamic_analysis", {})
    vm_runtime = report_data.get("vm_runtime", {})
    overview = (
        f"Analyzed {project.get('file_count', 0)} files. "
        f"Execution verdict is {summary.get('execution_verdict', 'not-run')}, "
        f"with {summary.get('total_findings', 0)} total findings."
    )
    if languages:
        overview += f" Programming languages detected: {', '.join(languages)}."
    risk_narrative = (
        f"The current run contains {high_or_critical} high-severity or critical findings and "
        f"a calculated risk score of {summary.get('risk_score', 0)}/100."
    )
    blockers = [
        action["recommendation"]
        for action in summary.get("next_actions", [])
        if action.get("severity") in {"critical", "high", "medium"}
    ][:3]
    quick_wins = [
        action["recommendation"]
        for action in summary.get("next_actions", [])
        if action.get("severity") in {"low", "info", "medium"}
    ][:3]
    if not blockers:
        blockers = ["No immediate release blockers were synthesized from the current finding set."]
    if not quick_wins:
        quick_wins = ["Re-run the scan after the next code change to confirm the baseline remains stable."]
    root_causes: list[str] = []
    if high_or_critical:
        root_causes.append("High-severity findings are still present in the current revision.")
    if lifecycle.get("persisting_count"):
        root_causes.append("Some findings persisted from the previous baseline and were not removed by the latest change set.")
    if dependencies.get("flag_counts", {}).get("unpinned"):
        root_causes.append("Dependency manifests contain unpinned constraints that weaken release reproducibility.")
    fix_strategy = [
        "Resolve the highest-severity issues first and rerun the focused checks on the touched files.",
        "Stabilize build and test execution before accepting release readiness.",
    ]
    suggested_tests = [
        "Add or extend regression tests around the files with high-severity findings.",
        "Keep one full-project retest in the release pipeline even after focused reruns.",
    ]
    fuzz_targets = [
        "Prioritize parsers, deserializers, and file-loading boundaries for fuzz harness coverage.",
    ]
    dependency_notes = []
    if dependencies.get("component_count", 0):
        dependency_notes.append(
            f"Dependency inventory detected {dependencies.get('component_count', 0)} components "
            f"across {dependencies.get('manifest_count', 0)} manifests."
        )
        if dependencies.get("flag_counts", {}).get("external-source"):
            dependency_notes.append("Some dependency entries reference external URLs or VCS sources and should be reviewed.")
    crash_clusters: list[str] = []
    runtime_explanations: list[str] = []
    patch_candidates: list[str] = []
    regression_tests = list(suggested_tests)
    if dynamic_analysis.get("sanitizer_built") and not dynamic_analysis.get("sanitizer_tests_ran"):
        runtime_explanations.append("The sanitizer build succeeded, but there were no runnable test entry points in the instrumented profile.")
    if dynamic_analysis.get("sanitizer_tests_ran"):
        crash_clusters.append("Group sanitizer failures by stack trace prefix and affected module before patching.")
        patch_candidates.append("Add bounds checks and ownership fixes in the modules touched by sanitizer-backed failures.")
        regression_tests.append("Re-run sanitizer-backed tests on the patched modules and the adjacent parser surface.")
    if service_runtime.get("source_correlated_paths", 0):
        runtime_explanations.append(
            f"Controlled verification confirmed {service_runtime.get('source_correlated_paths', 0)} HTTP paths against the runtime target."
        )
        regression_tests.append("Replay the verified HTTP requests after each release candidate build.")
    if vm_runtime.get("process_trace_collected"):
        crash_clusters.append("Use the captured process trace to cluster failures by child process tree and executed binary.")
    if dependency_diff.get("new_vulnerable_count", 0):
        patch_candidates.append("Update or replace the newly introduced vulnerable dependencies before release.")
    return {
        "source": "local-fallback",
        "provider": backend["provider"],
        "mode": backend["mode"],
        "model": DEFAULT_ASSISTANT_MODEL["label"],
        "active_playbooks": _playbook_titles(playbook_ids),
        "playbook_ids": playbook_ids,
        "routing_reason": str(backend.get("routing_reason", "") or ""),
        "reason": reason or "AI backend is disabled or not configured, so a deterministic local fallback review was generated.",
        "overview": overview,
        "release_decision": _release_decision(summary),
        "risk_narrative": risk_narrative,
        "blockers": blockers,
        "quick_wins": quick_wins,
        "root_causes": root_causes[:4],
        "fix_strategy": fix_strategy[:4],
        "suggested_tests": suggested_tests[:4],
        "fuzz_targets": fuzz_targets[:4],
        "dependency_notes": dependency_notes[:4],
        "crash_clusters": crash_clusters[:4],
        "runtime_explanations": runtime_explanations[:4],
        "patch_candidates": patch_candidates[:4],
        "regression_tests": regression_tests[:5],
        "confidence": "medium",
    }


def _build_prompt(report_data: dict[str, Any]) -> str:
    playbook_ids = select_active_playbooks(report_data)
    summary = report_data["summary"]
    project = report_data["project"]
    findings = report_data["findings"][:8]
    prompt = {
        "playbooks": {
            "ids": playbook_ids,
            "titles": _playbook_titles(playbook_ids),
        },
        "job": {
            "name": report_data["job"]["name"],
            "mode": report_data["job"]["mode"],
            "input": report_data["job"]["original_filename"],
        },
        "summary": {
            "risk_score": summary.get("risk_score", 0),
            "highest_severity": summary.get("highest_severity", "info"),
            "execution_verdict": summary.get("execution_verdict", "not-run"),
            "total_findings": summary.get("total_findings", 0),
            "selected_checks": summary.get("selected_checks", []),
            "severity_counts": summary.get("severity_counts", {}),
        },
        "project": {
            "is_qt_project": project.get("is_qt_project", False),
            "build_systems": project.get("build_systems", []),
            "has_tests": project.get("has_tests", False),
            "file_count": project.get("file_count", 0),
            "programming_languages": project.get("programming_languages", []),
            "polyglot": project.get("polyglot", False),
        },
        "dependency_diff": report_data.get("dependency_diff", {}),
        "service_runtime": report_data.get("service_runtime", {}),
        "dynamic_analysis": report_data.get("dynamic_analysis", {}),
        "vm_runtime": report_data.get("vm_runtime", {}),
        "top_findings": findings,
    }
    return (
        "You are a senior AppSec and C++/Qt release reviewer. "
        "Read the scan snapshot and respond with strict JSON only. "
        "Schema: {"
        "\"overview\": string, "
        "\"release_decision\": string, "
        "\"risk_narrative\": string, "
        "\"blockers\": [string], "
        "\"quick_wins\": [string], "
        "\"root_causes\": [string], "
        "\"fix_strategy\": [string], "
        "\"suggested_tests\": [string], "
        "\"fuzz_targets\": [string], "
        "\"dependency_notes\": [string], "
        "\"crash_clusters\": [string], "
        "\"runtime_explanations\": [string], "
        "\"patch_candidates\": [string], "
        "\"regression_tests\": [string], "
        "\"confidence\": string"
        "}.\n"
        f"Input JSON:\n{json.dumps(prompt, ensure_ascii=False, indent=2)}"
    )


def _extract_json_block(content: str) -> dict[str, Any] | None:
    stripped = content.strip()
    candidates = [stripped]
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, flags=re.DOTALL)
    candidates.extend(fenced)
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _remote_review(report_data: dict[str, Any], backend: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    settings = get_ai_settings()
    logs: list[str] = []
    playbook_ids = list(backend.get("selected_playbooks") or select_active_playbooks(report_data))
    headers = {"Content-Type": "application/json"}
    if settings["api_key"]:
        headers["Authorization"] = f"Bearer {settings['api_key']}"
    payload = {
        "model": settings["model"],
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": "Return only valid JSON. Do not use markdown.",
            },
            {
                "role": "user",
                "content": _build_prompt(report_data),
            },
        ],
    }
    logs.append(f"AI analyzer request prepared for provider {backend['provider']} using model {backend['model']}.")
    client_factory = _httpx_client_factory()
    if client_factory is not None:
        try:
            with client_factory(timeout=int(settings["timeout_seconds"])) as client:
                response = client.post(str(settings["url"]), headers=headers, json=payload)
                response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            logs.append(f"AI analyzer request failed: {exc}")
            return None, logs
        except ValueError:
            logs.append("AI analyzer response was not valid JSON.")
            return None, logs
    else:
        request = Request(
            str(settings["url"]),
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=int(settings["timeout_seconds"])) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (OSError, HTTPError, URLError, ValueError) as exc:
            logs.append(f"AI analyzer request failed: {exc}")
            return None, logs

    content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
    parsed = _extract_json_block(content)
    if not parsed:
        logs.append("AI analyzer returned content that could not be parsed into the expected JSON schema.")
        return None, logs

    review = {
        "source": "remote-ai",
        "provider": backend["provider"],
        "mode": backend["mode"],
        "model": backend["model"],
        "active_playbooks": _playbook_titles(playbook_ids),
        "playbook_ids": playbook_ids,
        "routing_reason": str(backend.get("routing_reason", "") or ""),
        "reason": "Generated by the configured AI review backend.",
        "overview": str(parsed.get("overview", "")).strip(),
        "release_decision": str(parsed.get("release_decision", "review-before-release")).strip(),
        "risk_narrative": str(parsed.get("risk_narrative", "")).strip(),
        "blockers": [str(item).strip() for item in parsed.get("blockers", []) if str(item).strip()][:5],
        "quick_wins": [str(item).strip() for item in parsed.get("quick_wins", []) if str(item).strip()][:5],
        "root_causes": [str(item).strip() for item in parsed.get("root_causes", []) if str(item).strip()][:5],
        "fix_strategy": [str(item).strip() for item in parsed.get("fix_strategy", []) if str(item).strip()][:5],
        "suggested_tests": [str(item).strip() for item in parsed.get("suggested_tests", []) if str(item).strip()][:5],
        "fuzz_targets": [str(item).strip() for item in parsed.get("fuzz_targets", []) if str(item).strip()][:5],
        "dependency_notes": [str(item).strip() for item in parsed.get("dependency_notes", []) if str(item).strip()][:5],
        "crash_clusters": [str(item).strip() for item in parsed.get("crash_clusters", []) if str(item).strip()][:5],
        "runtime_explanations": [str(item).strip() for item in parsed.get("runtime_explanations", []) if str(item).strip()][:5],
        "patch_candidates": [str(item).strip() for item in parsed.get("patch_candidates", []) if str(item).strip()][:5],
        "regression_tests": [str(item).strip() for item in parsed.get("regression_tests", []) if str(item).strip()][:5],
        "confidence": str(parsed.get("confidence", "medium")).strip(),
    }
    return review, logs


def _local_llm_review(report_data: dict[str, Any], backend: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    model = backend.get("active_local_model")
    runner_path = _detect_local_runner()
    playbook_ids = list(backend.get("selected_playbooks") or select_active_playbooks(report_data))
    if not isinstance(model, dict) or not runner_path:
        return None, ["No local LLM model or llama.cpp runner is available."]

    logs = [f"Using local model {model['label']} through {runner_path}."]
    result = subprocess.run(
        [
            runner_path,
            "-m",
            str(model["path"]),
            "-c",
            "4096",
            "-n",
            "700",
            "-p",
            _build_prompt(report_data),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    logs.append(f"$ {runner_path} -m {model['path']} -c 4096 -n 700 -p <prompt>")
    if result.stderr.strip():
        logs.append(result.stderr.strip())
    if result.returncode != 0:
        logs.append("Local LLM process finished with a non-zero exit code.")
        return None, logs

    parsed = _extract_json_block(result.stdout)
    if not parsed:
        logs.append("Local LLM output could not be parsed as JSON.")
        return None, logs

    return (
        {
            "source": "local-llm",
            "provider": backend["provider"],
            "mode": backend["mode"],
            "model": model["label"],
            "active_playbooks": _playbook_titles(playbook_ids),
            "playbook_ids": playbook_ids,
            "routing_reason": str(backend.get("routing_reason", "") or ""),
            "reason": "Generated by a locally installed GGUF model through llama.cpp.",
            "overview": str(parsed.get("overview", "")).strip(),
            "release_decision": str(parsed.get("release_decision", "review-before-release")).strip(),
            "risk_narrative": str(parsed.get("risk_narrative", "")).strip(),
            "blockers": [str(item).strip() for item in parsed.get("blockers", []) if str(item).strip()][:5],
            "quick_wins": [str(item).strip() for item in parsed.get("quick_wins", []) if str(item).strip()][:5],
            "root_causes": [str(item).strip() for item in parsed.get("root_causes", []) if str(item).strip()][:5],
            "fix_strategy": [str(item).strip() for item in parsed.get("fix_strategy", []) if str(item).strip()][:5],
            "suggested_tests": [str(item).strip() for item in parsed.get("suggested_tests", []) if str(item).strip()][:5],
            "fuzz_targets": [str(item).strip() for item in parsed.get("fuzz_targets", []) if str(item).strip()][:5],
            "dependency_notes": [str(item).strip() for item in parsed.get("dependency_notes", []) if str(item).strip()][:5],
            "crash_clusters": [str(item).strip() for item in parsed.get("crash_clusters", []) if str(item).strip()][:5],
            "runtime_explanations": [str(item).strip() for item in parsed.get("runtime_explanations", []) if str(item).strip()][:5],
            "patch_candidates": [str(item).strip() for item in parsed.get("patch_candidates", []) if str(item).strip()][:5],
            "regression_tests": [str(item).strip() for item in parsed.get("regression_tests", []) if str(item).strip()][:5],
            "confidence": str(parsed.get("confidence", "medium")).strip(),
        },
        logs,
    )


def generate_ai_review(report_data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    backend = _review_backend(report_data)
    if backend["configured"]:
        if backend["mode"] == "remote-ai":
            review, logs = _remote_review(report_data, backend)
            if review:
                return review, logs
            if backend.get("active_local_model"):
                local_backend = dict(backend)
                local_backend["mode"] = "local-llm"
                local_backend["provider"] = "llama.cpp"
                local_backend["model"] = backend["active_local_model"]["label"]
                local_review, local_logs = _local_llm_review(report_data, local_backend)
                merged_logs = list(logs) + list(local_logs)
                if local_review:
                    return local_review, merged_logs
                return _fallback_review(report_data, backend, reason="Remote and local AI reviews both failed, so the portal generated a local fallback review."), merged_logs
            return _fallback_review(report_data, backend, reason="Remote AI review failed, so the portal generated a local fallback review."), logs
        if backend["mode"] == "local-llm":
            review, logs = _local_llm_review(report_data, backend)
            if review:
                return review, logs
            remote_backend = dict(backend)
            remote_backend["mode"] = "remote-ai"
            remote_backend["provider"] = str(get_ai_settings().get("provider", "openai-compatible") or "openai-compatible")
            remote_backend["model"] = str(get_ai_settings().get("model", "") or "not set")
            review, remote_logs = _remote_review(report_data, remote_backend)
            merged_logs = list(logs) + list(remote_logs)
            if review:
                return review, merged_logs
            return _fallback_review(report_data, backend, reason="Local-first routing failed for both local and remote AI backends, so the portal generated a local fallback review."), merged_logs
        return _fallback_review(report_data, backend), [
            "Routing mode keeps the review on deterministic fallback despite remote configuration."
        ]

    if backend["mode"] == "local-llm":
        review, logs = _local_llm_review(report_data, backend)
        if review:
            return review, logs
        return _fallback_review(report_data, backend, reason="Local LLM review failed, so the portal generated a local fallback review."), logs

    return _fallback_review(report_data, backend), [
        "AI analyzer not configured; generated a local fallback review."
    ]


def build_ai_review_markdown(review: dict[str, Any], output_path: Path) -> None:
    lines = [
        "# AI Review",
        "",
        f"Source: {review.get('source', 'unknown')}",
        f"Provider: {review.get('provider', 'unknown')}",
        f"Model: {review.get('model', 'unknown')}",
        f"Confidence: {review.get('confidence', 'unknown')}",
        f"Release decision: {review.get('release_decision', 'unknown')}",
        "",
        "## Active Playbooks",
    ]
    active_playbooks = review.get("active_playbooks", []) or ["No active playbooks were selected."]
    lines.extend(f"- {item}" for item in active_playbooks)
    lines.extend(
        [
            "",
            "## Routing",
            review.get("routing_reason", "") or "No routing note generated.",
            "",
        ]
    )
    lines.extend(
        [
        "## Overview",
        review.get("overview", "No overview generated."),
        "",
        "## Risk Narrative",
        review.get("risk_narrative", "No risk narrative generated."),
        "",
        "## Blockers",
        ]
    )
    blockers = review.get("blockers", []) or ["No blockers generated."]
    lines.extend(f"- {item}" for item in blockers)
    lines.extend(["", "## Quick Wins"])
    quick_wins = review.get("quick_wins", []) or ["No quick wins generated."]
    lines.extend(f"- {item}" for item in quick_wins)
    lines.extend(["", "## Root Causes"])
    root_causes = review.get("root_causes", []) or ["No root causes synthesized."]
    lines.extend(f"- {item}" for item in root_causes)
    lines.extend(["", "## Fix Strategy"])
    fix_strategy = review.get("fix_strategy", []) or ["No fix strategy synthesized."]
    lines.extend(f"- {item}" for item in fix_strategy)
    lines.extend(["", "## Suggested Tests"])
    suggested_tests = review.get("suggested_tests", []) or ["No suggested tests synthesized."]
    lines.extend(f"- {item}" for item in suggested_tests)
    lines.extend(["", "## Fuzz Targets"])
    fuzz_targets = review.get("fuzz_targets", []) or ["No fuzz targets synthesized."]
    lines.extend(f"- {item}" for item in fuzz_targets)
    lines.extend(["", "## Dependency Notes"])
    dependency_notes = review.get("dependency_notes", []) or ["No dependency notes synthesized."]
    lines.extend(f"- {item}" for item in dependency_notes)
    lines.extend(["", "## Crash Clusters"])
    crash_clusters = review.get("crash_clusters", []) or ["No crash clusters synthesized."]
    lines.extend(f"- {item}" for item in crash_clusters)
    lines.extend(["", "## Runtime Explanations"])
    runtime_explanations = review.get("runtime_explanations", []) or ["No runtime explanations synthesized."]
    lines.extend(f"- {item}" for item in runtime_explanations)
    lines.extend(["", "## Patch Candidates"])
    patch_candidates = review.get("patch_candidates", []) or ["No patch candidates synthesized."]
    lines.extend(f"- {item}" for item in patch_candidates)
    lines.extend(["", "## Regression Tests"])
    regression_tests = review.get("regression_tests", []) or ["No regression tests synthesized."]
    lines.extend(f"- {item}" for item in regression_tests)
    lines.extend(["", "## Note", review.get("reason", "") or "No additional note."])
    output_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
