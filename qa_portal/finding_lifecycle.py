from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import FINDING_LIFECYCLE_DIR
from .models import Finding


VALID_REVIEW_STATES = {
    "open",
    "accepted-risk",
    "false-positive",
    "muted",
    "fixed-intended",
}


# Строим стабильный отпечаток по сути находки, чтобы сравнивать прогоны между собой.
def finding_fingerprint(finding: Finding) -> str:
    identity = "|".join(
        [
            finding.category.strip().casefold(),
            finding.title.strip().casefold(),
            finding.path.strip().casefold(),
            str(finding.line or 0),
            finding.source.strip().casefold(),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def hydrate_finding_fingerprints(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        if not finding.fingerprint:
            finding.fingerprint = finding_fingerprint(finding)
    return findings


def _project_state_path(project_key: str) -> Path:
    safe_key = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in project_key.strip().casefold())
    return FINDING_LIFECYCLE_DIR / f"{safe_key or 'project'}.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_project_review_states(project_key: str) -> dict[str, dict[str, Any]]:
    path = _project_state_path(project_key)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    states = payload.get("states", {}) if isinstance(payload, dict) else {}
    return states if isinstance(states, dict) else {}


def save_project_review_states(project_key: str, states: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    path = _project_state_path(project_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "project_key": project_key,
        "updated_at": _utc_now(),
        "states": states,
    }
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(path.parent),
    ) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(path)
    return states


# Подмешиваем ручные решения оператора к текущим находкам.
def apply_review_states(project_key: str, findings: list[Finding]) -> dict[str, Any]:
    hydrate_finding_fingerprints(findings)
    states = load_project_review_states(project_key)
    state_counts: dict[str, int] = {}
    muted_active = 0
    now = datetime.now(timezone.utc)
    for finding in findings:
        state = states.get(finding.fingerprint, {})
        review_state = str(state.get("review_state", "open"))
        if review_state not in VALID_REVIEW_STATES:
            review_state = "open"
        finding.review_state = review_state
        finding.review_note = str(state.get("review_note", "")).strip()
        muted_until = state.get("muted_until")
        finding.muted_until = str(muted_until).strip() if muted_until else None
        state_counts[review_state] = state_counts.get(review_state, 0) + 1
        if finding.muted_until:
            try:
                muted_dt = datetime.fromisoformat(finding.muted_until)
            except ValueError:
                muted_dt = None
            if muted_dt and muted_dt.tzinfo is None:
                muted_dt = muted_dt.replace(tzinfo=timezone.utc)
            if muted_dt and muted_dt >= now:
                muted_active += 1
    return {
        "review_state_counts": state_counts,
        "muted_active_count": muted_active,
        "tracked_decisions": len(states),
    }


def set_review_state(
    project_key: str,
    fingerprint: str,
    *,
    review_state: str,
    review_note: str = "",
    muted_until: str | None = None,
) -> dict[str, Any]:
    if review_state not in VALID_REVIEW_STATES:
        raise ValueError(f"Unsupported review state: {review_state}")
    states = load_project_review_states(project_key)
    states[fingerprint] = {
        "review_state": review_state,
        "review_note": review_note.strip(),
        "muted_until": muted_until or None,
        "updated_at": _utc_now(),
    }
    save_project_review_states(project_key, states)
    return states[fingerprint]


# Сравниваем текущие находки с базовым прогоном и помечаем каждую по жизненному циклу.
def compare_with_baseline(current_findings: list[Finding], baseline_findings: list[Finding]) -> dict[str, Any]:
    hydrate_finding_fingerprints(current_findings)
    hydrate_finding_fingerprints(baseline_findings)
    baseline_by_fp = {finding.fingerprint: finding for finding in baseline_findings}
    current_by_fp = {finding.fingerprint: finding for finding in current_findings}

    new_items: list[dict[str, Any]] = []
    persisting_items: list[dict[str, Any]] = []
    fixed_items: list[dict[str, Any]] = []

    for finding in current_findings:
        if finding.fingerprint in baseline_by_fp:
            finding.lifecycle_state = "persisting"
            persisting_items.append(_finding_summary(finding))
        else:
            finding.lifecycle_state = "new"
            new_items.append(_finding_summary(finding))

    for fingerprint, finding in baseline_by_fp.items():
        if fingerprint in current_by_fp:
            continue
        fixed_items.append(_finding_summary(finding))

    return {
        "baseline_total": len(baseline_findings),
        "current_total": len(current_findings),
        "new_count": len(new_items),
        "persisting_count": len(persisting_items),
        "fixed_count": len(fixed_items),
        "new_findings": new_items[:25],
        "persisting_findings": persisting_items[:25],
        "fixed_findings": fixed_items[:25],
    }


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        "fingerprint": finding.fingerprint,
        "category": finding.category,
        "severity": finding.severity,
        "title": finding.title,
        "path": finding.path,
        "line": finding.line,
        "source": finding.source,
    }
