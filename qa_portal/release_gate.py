from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any

from .config import RELEASE_GATE_POLICY_PATH


DEFAULT_POLICY = {
    "block_on_critical_findings": True,
    "block_on_new_high_findings": True,
    "block_on_new_critical_findings": True,
    "block_on_new_vulnerable_dependencies": True,
    "block_on_new_reachable_vulnerable_dependencies": True,
    "block_on_dependency_baseline_regression": True,
    "review_on_persisting_high_findings": True,
    "review_on_risk_score_regression": True,
    "review_on_net_new_findings": True,
    "review_on_high_severity_regression": True,
    "review_on_risk_score_above": 55,
}


def _load_policy() -> dict[str, Any]:
    if not RELEASE_GATE_POLICY_PATH.exists():
        return dict(DEFAULT_POLICY)
    try:
        payload = json.loads(RELEASE_GATE_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_POLICY)
    if not isinstance(payload, dict):
        return dict(DEFAULT_POLICY)
    merged = dict(DEFAULT_POLICY)
    merged.update(payload)
    return merged


def _coerce_bool(value: Any, default: bool) -> bool:
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


# Нормализуем policy-слой, чтобы release gate и UI использовали один и тот же набор значений.
def get_release_gate_policy() -> dict[str, Any]:
    raw = _load_policy()
    policy = {
        "block_on_critical_findings": _coerce_bool(raw.get("block_on_critical_findings"), DEFAULT_POLICY["block_on_critical_findings"]),
        "block_on_new_high_findings": _coerce_bool(raw.get("block_on_new_high_findings"), DEFAULT_POLICY["block_on_new_high_findings"]),
        "block_on_new_critical_findings": _coerce_bool(raw.get("block_on_new_critical_findings"), DEFAULT_POLICY["block_on_new_critical_findings"]),
        "block_on_new_vulnerable_dependencies": _coerce_bool(
            raw.get("block_on_new_vulnerable_dependencies"),
            DEFAULT_POLICY["block_on_new_vulnerable_dependencies"],
        ),
        "block_on_new_reachable_vulnerable_dependencies": _coerce_bool(
            raw.get("block_on_new_reachable_vulnerable_dependencies"),
            DEFAULT_POLICY["block_on_new_reachable_vulnerable_dependencies"],
        ),
        "block_on_dependency_baseline_regression": _coerce_bool(
            raw.get("block_on_dependency_baseline_regression"),
            DEFAULT_POLICY["block_on_dependency_baseline_regression"],
        ),
        "review_on_persisting_high_findings": _coerce_bool(
            raw.get("review_on_persisting_high_findings"),
            DEFAULT_POLICY["review_on_persisting_high_findings"],
        ),
        "review_on_risk_score_regression": _coerce_bool(
            raw.get("review_on_risk_score_regression"),
            DEFAULT_POLICY["review_on_risk_score_regression"],
        ),
        "review_on_net_new_findings": _coerce_bool(
            raw.get("review_on_net_new_findings"),
            DEFAULT_POLICY["review_on_net_new_findings"],
        ),
        "review_on_high_severity_regression": _coerce_bool(
            raw.get("review_on_high_severity_regression"),
            DEFAULT_POLICY["review_on_high_severity_regression"],
        ),
        "review_on_risk_score_above": max(0, min(_coerce_int(raw.get("review_on_risk_score_above"), DEFAULT_POLICY["review_on_risk_score_above"]), 100)),
    }
    policy["source"] = "file" if Path(RELEASE_GATE_POLICY_PATH).exists() else "default"
    return policy


# Сохраняем release gate policy локально, чтобы ею можно было управлять из Settings без ручной правки JSON.
def save_release_gate_policy(payload: dict[str, Any]) -> dict[str, Any]:
    current = get_release_gate_policy()
    stored = {
        "block_on_critical_findings": _coerce_bool(payload.get("block_on_critical_findings"), current["block_on_critical_findings"]),
        "block_on_new_high_findings": _coerce_bool(payload.get("block_on_new_high_findings"), current["block_on_new_high_findings"]),
        "block_on_new_critical_findings": _coerce_bool(payload.get("block_on_new_critical_findings"), current["block_on_new_critical_findings"]),
        "block_on_new_vulnerable_dependencies": _coerce_bool(
            payload.get("block_on_new_vulnerable_dependencies"),
            current["block_on_new_vulnerable_dependencies"],
        ),
        "block_on_new_reachable_vulnerable_dependencies": _coerce_bool(
            payload.get("block_on_new_reachable_vulnerable_dependencies"),
            current["block_on_new_reachable_vulnerable_dependencies"],
        ),
        "block_on_dependency_baseline_regression": _coerce_bool(
            payload.get("block_on_dependency_baseline_regression"),
            current["block_on_dependency_baseline_regression"],
        ),
        "review_on_persisting_high_findings": _coerce_bool(
            payload.get("review_on_persisting_high_findings"),
            current["review_on_persisting_high_findings"],
        ),
        "review_on_risk_score_regression": _coerce_bool(
            payload.get("review_on_risk_score_regression"),
            current["review_on_risk_score_regression"],
        ),
        "review_on_net_new_findings": _coerce_bool(
            payload.get("review_on_net_new_findings"),
            current["review_on_net_new_findings"],
        ),
        "review_on_high_severity_regression": _coerce_bool(
            payload.get("review_on_high_severity_regression"),
            current["review_on_high_severity_regression"],
        ),
        "review_on_risk_score_above": max(
            0,
            min(
                _coerce_int(payload.get("review_on_risk_score_above"), current["review_on_risk_score_above"]),
                100,
            ),
        ),
    }
    RELEASE_GATE_POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=str(RELEASE_GATE_POLICY_PATH.parent),
    ) as handle:
        json.dump(stored, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(RELEASE_GATE_POLICY_PATH)
    return get_release_gate_policy()


def release_gate_policy_status() -> dict[str, Any]:
    policy = get_release_gate_policy()
    block_keys = [key for key in policy if key.startswith("block_on_") and bool(policy.get(key))]
    review_keys = [key for key in policy if key.startswith("review_on_") and key != "review_on_risk_score_above" and bool(policy.get(key))]
    return {
        "policy": policy,
        "enabled_blockers": len(block_keys),
        "enabled_reviews": len(review_keys),
        "baseline_aware": any(
            bool(policy.get(key))
            for key in (
                "block_on_new_high_findings",
                "block_on_new_critical_findings",
                "block_on_new_vulnerable_dependencies",
                "block_on_new_reachable_vulnerable_dependencies",
                "block_on_dependency_baseline_regression",
                "review_on_persisting_high_findings",
                "review_on_risk_score_regression",
                "review_on_net_new_findings",
                "review_on_high_severity_regression",
            )
        ),
    }


def _policy_hit(rule_id: str, level: str, message: str, value: Any, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    hit = {
        "rule_id": rule_id,
        "level": level,
        "message": message,
        "value": value,
    }
    if details:
        hit["details"] = details
    return hit


# Release gate принимает решение независимо от AI и опирается на baseline/lifecycle/SCA.
def evaluate_release_gate(report_data: dict[str, Any]) -> dict[str, Any]:
    policy = get_release_gate_policy()
    summary = report_data.get("summary", {})
    lifecycle = report_data.get("finding_lifecycle", {})
    dependency_diff = report_data.get("dependency_diff", {})
    dependencies = report_data.get("dependencies", {})
    baseline_snapshot = report_data.get("baseline_snapshot", {})
    comparison = report_data.get("comparison", {})
    comparison_baseline_available = comparison.get("baseline_available")
    if comparison_baseline_available is None:
        comparison_baseline_available = bool(comparison.get("baseline_job_id"))
    baseline_available = bool(baseline_snapshot) or bool(comparison_baseline_available)

    hits: list[dict[str, Any]] = []
    critical_count = int((summary.get("severity_counts") or {}).get("critical", 0))
    if policy.get("block_on_critical_findings") and critical_count > 0:
        hits.append(
            _policy_hit(
                "critical-findings",
                "block",
                "В проекте есть критические находки.",
                critical_count,
            )
        )

    if policy.get("block_on_new_high_findings") and int(lifecycle.get("new_high_count", 0)) > 0:
        hits.append(
            _policy_hit(
                "new-high-findings",
                "block",
                "Появились новые high-находки относительно baseline.",
                int(lifecycle.get("new_high_count", 0)),
            )
        )

    if policy.get("block_on_new_critical_findings") and int(lifecycle.get("new_critical_count", 0)) > 0:
        hits.append(
            _policy_hit(
                "new-critical-findings",
                "block",
                "Появились новые critical-находки относительно baseline.",
                int(lifecycle.get("new_critical_count", 0)),
            )
        )

    if policy.get("block_on_new_vulnerable_dependencies") and int(dependency_diff.get("new_vulnerable_count", 0)) > 0:
        hits.append(
            _policy_hit(
                "new-vulnerable-dependencies",
                "block",
                "В релиз вошли новые уязвимые зависимости.",
                int(dependency_diff.get("new_vulnerable_count", 0)),
            )
        )

    if (
        policy.get("block_on_new_reachable_vulnerable_dependencies")
        and int(dependency_diff.get("new_reachable_vulnerable_count", 0)) > 0
    ):
        hits.append(
            _policy_hit(
                "new-reachable-vulnerable-dependencies",
                "block",
                "Появились новые достижимые уязвимые зависимости относительно baseline.",
                int(dependency_diff.get("new_reachable_vulnerable_count", 0)),
            )
        )

    if policy.get("block_on_dependency_baseline_regression") and int(dependency_diff.get("dependency_regression_count", 0)) > 0:
        hits.append(
            _policy_hit(
                "dependency-baseline-regression",
                "block",
                "Часть уже известных зависимостей стала хуже относительно baseline.",
                int(dependency_diff.get("dependency_regression_count", 0)),
            )
        )

    if policy.get("review_on_persisting_high_findings") and int(lifecycle.get("persisting_high_count", 0)) > 0:
        hits.append(
            _policy_hit(
                "persisting-high-findings",
                "review",
                "Часть high-находок сохраняется из предыдущего baseline.",
                int(lifecycle.get("persisting_high_count", 0)),
            )
        )

    baseline_risk_score = baseline_snapshot.get("risk_score")
    current_risk_score = int(summary.get("risk_score", 0))
    if (
        policy.get("review_on_risk_score_regression")
        and baseline_risk_score is not None
        and current_risk_score > int(baseline_risk_score)
    ):
        hits.append(
            _policy_hit(
                "risk-score-regression",
                "review",
                "Risk score ухудшился относительно baseline.",
                f"{int(baseline_risk_score)} -> {current_risk_score}",
                details={
                    "baseline_risk_score": int(baseline_risk_score),
                    "current_risk_score": current_risk_score,
                },
            )
        )

    if (
        policy.get("review_on_net_new_findings")
        and baseline_available
        and int(lifecycle.get("new_count", 0)) > int(lifecycle.get("fixed_count", 0))
    ):
        hits.append(
            _policy_hit(
                "net-new-findings-regression",
                "review",
                "Количество новых находок превышает число исправленных относительно baseline.",
                f"+{int(lifecycle.get('new_count', 0))} / -{int(lifecycle.get('fixed_count', 0))}",
            )
        )

    baseline_severity_counts = baseline_snapshot.get("severity_counts") or {}
    current_high_or_critical = int((summary.get("severity_counts") or {}).get("high", 0)) + int((summary.get("severity_counts") or {}).get("critical", 0))
    baseline_high_or_critical = int(baseline_severity_counts.get("high", 0)) + int(baseline_severity_counts.get("critical", 0))
    if (
        policy.get("review_on_high_severity_regression")
        and baseline_snapshot
        and current_high_or_critical > baseline_high_or_critical
    ):
        hits.append(
            _policy_hit(
                "high-severity-regression",
                "review",
                "Общее число high/critical-находок выросло относительно baseline.",
                f"{baseline_high_or_critical} -> {current_high_or_critical}",
                details={
                    "baseline_high_or_critical": baseline_high_or_critical,
                    "current_high_or_critical": current_high_or_critical,
                },
            )
        )

    risk_threshold = int(policy.get("review_on_risk_score_above", DEFAULT_POLICY["review_on_risk_score_above"]))
    if current_risk_score >= risk_threshold:
        hits.append(
            _policy_hit(
                "risk-score-threshold",
                "review",
                f"Risk score достиг порога {risk_threshold}.",
                current_risk_score,
            )
        )

    decision = "pass"
    if any(item["level"] == "block" for item in hits):
        decision = "block"
    elif hits:
        decision = "review"

    return {
        "policy": policy,
        "decision": decision,
        "hits": hits,
        "blocked": decision == "block",
        "requires_review": decision == "review",
        "baseline_snapshot": baseline_snapshot,
        "current_snapshot": {
            "risk_score": current_risk_score,
            "high_or_critical_findings": current_high_or_critical,
            "vulnerable_component_count": int(dependencies.get("vulnerable_component_count", 0)),
            "reachable_vulnerable_component_count": int(dependencies.get("reachable_vulnerable_component_count", 0)),
        },
    }
