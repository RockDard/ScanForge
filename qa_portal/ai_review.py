from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import httpx

from .config import get_ai_settings


def ai_backend_status() -> dict[str, Any]:
    settings = get_ai_settings()
    enabled = bool(settings["enabled"])
    configured = enabled and bool(settings["url"] and settings["model"])
    return {
        "enabled": enabled,
        "configured": configured,
        "provider": settings["provider"],
        "model": settings["model"] or "not set",
        "endpoint": settings["url"] or "not set",
        "mode": "remote-ai" if configured else "local-fallback",
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
    overview = (
        f"Analyzed {project.get('file_count', 0)} files. "
        f"Execution verdict is {summary.get('execution_verdict', 'not-run')}, "
        f"with {summary.get('total_findings', 0)} total findings."
    )
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

    content = (
        body.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    parsed = _extract_json_block(content)
    if not parsed:
        logs.append("AI analyzer returned content that could not be parsed into the expected JSON schema.")
        return None, logs

    review = {
        "source": "remote-ai",
        "provider": backend["provider"],
        "mode": backend["mode"],
        "reason": "Generated by the configured AI review backend.",
        "overview": str(parsed.get("overview", "")).strip(),
        "release_decision": str(parsed.get("release_decision", "review-before-release")).strip(),
        "risk_narrative": str(parsed.get("risk_narrative", "")).strip(),
        "blockers": [str(item).strip() for item in parsed.get("blockers", []) if str(item).strip()][:5],
        "quick_wins": [str(item).strip() for item in parsed.get("quick_wins", []) if str(item).strip()][:5],
        "confidence": str(parsed.get("confidence", "medium")).strip(),
    }
    return review, logs


def generate_ai_review(report_data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    backend = ai_backend_status()
    if not backend["configured"]:
        return _fallback_review(report_data, backend), [
            "AI analyzer not configured; generated a local fallback review."
        ]

    review, logs = _remote_review(report_data, backend)
    if review:
        return review, logs
    return _fallback_review(report_data, backend, reason="Remote AI review failed, so the portal generated a local fallback review."), logs


def build_ai_review_markdown(review: dict[str, Any], output_path: Path) -> None:
    lines = [
        "# AI Review",
        "",
        f"Source: {review.get('source', 'unknown')}",
        f"Provider: {review.get('provider', 'unknown')}",
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
