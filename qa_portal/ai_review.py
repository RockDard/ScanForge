from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import httpx

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


def preferred_local_model() -> dict[str, Any] | None:
    runner_path = _detect_local_runner()
    if not runner_path:
        return None
    models = list_local_models()
    installed = [item for item in models if item.get("installed")]
    if not installed:
        return None
    installed.sort(key=lambda item: (not item.get("default", False), item["label"]))
    return installed[0]


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
    remote_configured = remote_enabled and bool(settings["url"] and settings["model"])
    local_runner = _detect_local_runner()
    local_model = preferred_local_model()
    local_models = list_local_models()
    active_mode = "local-fallback"
    provider = "scanforge-local"
    model_name = DEFAULT_ASSISTANT_MODEL["label"]
    if remote_configured:
        active_mode = "remote-ai"
        provider = str(settings["provider"])
        model_name = str(settings["model"] or "not set")
    elif local_model:
        active_mode = "local-llm"
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
    high_or_critical = summary["severity_counts"].get("critical", 0) + summary["severity_counts"].get("high", 0)
    languages = project.get("programming_languages", [])
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
    return {
        "source": "local-fallback",
        "provider": backend["provider"],
        "mode": backend["mode"],
        "model": DEFAULT_ASSISTANT_MODEL["label"],
        "reason": reason or "AI backend is disabled or not configured, so a deterministic local fallback review was generated.",
        "overview": overview,
        "release_decision": _release_decision(summary),
        "risk_narrative": risk_narrative,
        "blockers": blockers,
        "quick_wins": quick_wins,
        "confidence": "medium",
    }


def _build_prompt(report_data: dict[str, Any]) -> str:
    summary = report_data["summary"]
    project = report_data["project"]
    findings = report_data["findings"][:8]
    prompt = {
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
    try:
        with httpx.Client(timeout=int(settings["timeout_seconds"])) as client:
            response = client.post(str(settings["url"]), headers=headers, json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logs.append(f"AI analyzer request failed: {exc}")
        return None, logs

    try:
        body = response.json()
    except ValueError:
        logs.append("AI analyzer response was not valid JSON.")
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
        "reason": "Generated by the configured AI review backend.",
        "overview": str(parsed.get("overview", "")).strip(),
        "release_decision": str(parsed.get("release_decision", "review-before-release")).strip(),
        "risk_narrative": str(parsed.get("risk_narrative", "")).strip(),
        "blockers": [str(item).strip() for item in parsed.get("blockers", []) if str(item).strip()][:5],
        "quick_wins": [str(item).strip() for item in parsed.get("quick_wins", []) if str(item).strip()][:5],
        "confidence": str(parsed.get("confidence", "medium")).strip(),
    }
    return review, logs


def _local_llm_review(report_data: dict[str, Any], backend: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    model = preferred_local_model()
    runner_path = _detect_local_runner()
    if not model or not runner_path:
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
            "reason": "Generated by a locally installed GGUF model through llama.cpp.",
            "overview": str(parsed.get("overview", "")).strip(),
            "release_decision": str(parsed.get("release_decision", "review-before-release")).strip(),
            "risk_narrative": str(parsed.get("risk_narrative", "")).strip(),
            "blockers": [str(item).strip() for item in parsed.get("blockers", []) if str(item).strip()][:5],
            "quick_wins": [str(item).strip() for item in parsed.get("quick_wins", []) if str(item).strip()][:5],
            "confidence": str(parsed.get("confidence", "medium")).strip(),
        },
        logs,
    )


def generate_ai_review(report_data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    backend = ai_backend_status()
    if backend["configured"]:
        review, logs = _remote_review(report_data, backend)
        if review:
            return review, logs
        return _fallback_review(report_data, backend, reason="Remote AI review failed, so the portal generated a local fallback review."), logs

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
        "## Overview",
        review.get("overview", "No overview generated."),
        "",
        "## Risk Narrative",
        review.get("risk_narrative", "No risk narrative generated."),
        "",
        "## Blockers",
    ]
    blockers = review.get("blockers", []) or ["No blockers generated."]
    lines.extend(f"- {item}" for item in blockers)
    lines.extend(["", "## Quick Wins"])
    quick_wins = review.get("quick_wins", []) or ["No quick wins generated."]
    lines.extend(f"- {item}" for item in quick_wins)
    lines.extend(["", "## Note", review.get("reason", "") or "No additional note."])
    output_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
