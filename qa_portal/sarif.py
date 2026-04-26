from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from . import PROJECT_NAME, PROJECT_VERSION
from .finding_lifecycle import finding_fingerprint
from .models import Finding, Severity


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VALID_SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")
SEVERITY_FROM_SARIF_LEVEL: dict[str, Severity] = {
    "none": "info",
    "note": "low",
    "warning": "medium",
    "error": "high",
}
SARIF_LEVEL_FROM_SEVERITY: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
CONFIDENCE_VALUES = {"low", "medium", "high"}
SARIF_FILE_SUFFIXES = (".sarif", ".sarif.json")


def normalize_severity(value: object, *, default: Severity = "info") -> Severity:
    normalized = str(value or "").strip().lower()
    aliases: dict[str, Severity] = {
        "blocker": "critical",
        "fatal": "critical",
        "crit": "critical",
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "moderate": "medium",
        "minor": "low",
        "note": "low",
        "none": "info",
        "information": "info",
        "informational": "info",
    }
    if normalized in VALID_SEVERITIES:
        return normalized  # type: ignore[return-value]
    return aliases.get(normalized, default)


def normalize_finding_path(path: object, *, source_root: Path | None = None) -> str:
    raw = str(path or "").strip()
    if not raw:
        return ""
    windows_drive_path = re.match(r"^[A-Za-z]:[\\/]", raw)
    parsed = urlparse(raw) if not windows_drive_path else None
    if parsed and parsed.scheme == "file":
        raw = unquote(parsed.path)
    elif parsed and parsed.scheme and parsed.scheme not in {"", "file"}:
        raw = unquote(parsed.path or raw)
    raw = raw.replace("\\", "/")
    if re.match(r"^/[A-Za-z]:/", raw):
        raw = raw[1:]
    if source_root is not None:
        relative = _relative_to_source_root(raw, source_root)
        if relative is not None:
            return relative
    candidate = Path(raw)
    if source_root is not None and candidate.is_absolute():
        try:
            raw = candidate.resolve().relative_to(source_root.resolve()).as_posix()
        except (OSError, ValueError):
            raw = candidate.name
    else:
        raw = raw.lstrip("./")
    return raw


def normalize_line(value: object) -> int | None:
    try:
        line = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def normalize_confidence(value: object) -> str:
    normalized = str(value or "medium").strip().lower()
    return normalized if normalized in CONFIDENCE_VALUES else "medium"


def _relative_to_source_root(raw: str, source_root: Path) -> str | None:
    root = str(source_root).replace("\\", "/").rstrip("/")
    if re.match(r"^/[A-Za-z]:/", root):
        root = root[1:]
    value = raw.replace("\\", "/")
    root_key = root.casefold()
    value_key = value.casefold()
    if not root_key:
        return None
    if value_key == root_key:
        return ""
    prefix = f"{root_key}/"
    if value_key.startswith(prefix):
        return value[len(root) + 1 :].lstrip("./")
    return None


def normalize_references(references: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for reference in references or []:
        if not isinstance(reference, dict):
            continue
        ref_id = str(reference.get("id") or reference.get("guid") or reference.get("name") or "").strip()
        title = str(reference.get("title") or reference.get("name") or ref_id).strip()
        url = str(reference.get("url") or reference.get("helpUri") or "").strip()
        if not ref_id and not url:
            continue
        key = ref_id or url
        deduped[key] = {
            "id": ref_id or key,
            "title": title or ref_id or key,
            "url": url,
        }
    return list(deduped.values())


def stable_rule_id(finding: Finding) -> str:
    if finding.rule_id:
        return finding.rule_id
    seed = "|".join(
        [
            finding.source.strip().casefold(),
            finding.category.strip().casefold(),
            finding.title.strip().casefold(),
        ]
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.strip().casefold()).strip("-")
    return f"scanforge.{slug or 'finding'}.{digest}"


def normalize_finding(finding: Finding, *, source_root: Path | None = None) -> Finding:
    finding.category = (finding.category or "general").strip().casefold() or "general"
    finding.severity = normalize_severity(finding.severity)
    finding.title = (finding.title or "Untitled finding").strip() or "Untitled finding"
    finding.description = (finding.description or finding.title).strip() or finding.title
    finding.path = normalize_finding_path(finding.path, source_root=source_root)
    finding.line = normalize_line(finding.line)
    finding.source = (finding.source or "scanforge").strip() or "scanforge"
    finding.recommendation = (finding.recommendation or "").strip()
    finding.references = normalize_references(finding.references)
    finding.rule_id = stable_rule_id(finding)
    finding.confidence = normalize_confidence(finding.confidence)
    finding.evidence = (finding.evidence or "").strip()
    finding.trace = [item for item in finding.trace if isinstance(item, dict)]
    if not finding.fingerprint:
        finding.fingerprint = finding_fingerprint(finding)
    return finding


def normalize_findings(findings: list[Finding], *, source_root: Path | None = None) -> list[Finding]:
    return [normalize_finding(finding, source_root=source_root) for finding in findings]


def _message_text(message: dict[str, Any] | None) -> str:
    if not isinstance(message, dict):
        return ""
    return str(message.get("text") or message.get("markdown") or "").strip()


def _rule_lookup(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = ((run.get("tool") or {}).get("driver") or {})
    extensions = (run.get("tool") or {}).get("extensions") or []
    rules: dict[str, dict[str, Any]] = {}
    for tool_component in [driver, *[item for item in extensions if isinstance(item, dict)]]:
        for rule in tool_component.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id") or "").strip()
            if rule_id:
                rules[rule_id] = rule
    return rules


def _first_location(result: dict[str, Any]) -> tuple[str, int | None]:
    locations = result.get("locations") or []
    if not locations:
        return "", None
    physical = ((locations[0] or {}).get("physicalLocation") or {})
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    return str(artifact.get("uri") or ""), normalize_line(region.get("startLine"))


def _references_from_rule(rule: dict[str, Any]) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    help_uri = str(rule.get("helpUri") or "").strip()
    if help_uri:
        references.append(
            {
                "id": str(rule.get("id") or help_uri),
                "title": _message_text(rule.get("shortDescription")) or str(rule.get("name") or rule.get("id") or "Rule reference"),
                "url": help_uri,
            }
        )
    properties = rule.get("properties") or {}
    if isinstance(properties.get("references"), list):
        references.extend(item for item in properties["references"] if isinstance(item, dict))
    return normalize_references(references)


def import_sarif_file(path: Path, *, source_root: Path | None = None) -> list[Finding]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    findings: list[Finding] = []
    for run in payload.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = str(driver.get("name") or "SARIF").strip()
        rules = _rule_lookup(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or (result.get("rule") or {}).get("id") or "").strip()
            rule = rules.get(rule_id, {})
            path_uri, line = _first_location(result)
            properties = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            severity = normalize_severity(
                properties.get("scanforgeSeverity")
                or properties.get("severity")
                or SEVERITY_FROM_SARIF_LEVEL.get(str(result.get("level") or "").lower())
            )
            title = (
                _message_text(rule.get("shortDescription"))
                or str(rule.get("name") or "").strip()
                or rule_id
                or "Imported SARIF finding"
            )
            description = _message_text(result.get("message")) or _message_text(rule.get("fullDescription")) or title
            help_text = _message_text(rule.get("help"))
            finding = Finding(
                category=str(properties.get("scanforgeCategory") or "external-sast"),
                severity=severity,
                title=title,
                description=description,
                path=normalize_finding_path(path_uri, source_root=source_root),
                line=line,
                source=f"sarif:{tool_name}",
                recommendation=help_text,
                references=_references_from_rule(rule),
                rule_id=rule_id or stable_rule_id(
                    Finding(
                        category="external-sast",
                        severity=severity,
                        title=title,
                        description=description,
                        source=f"sarif:{tool_name}",
                    )
                ),
                confidence=normalize_confidence(properties.get("confidence")),
                evidence=description,
                fingerprint=str((result.get("partialFingerprints") or {}).get("scanforgeFingerprint") or ""),
            )
            findings.append(normalize_finding(finding, source_root=source_root))
    return findings


def find_sarif_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in {".git", ".hg", ".svn", "node_modules", "__pycache__"} for part in path.parts):
            continue
        if not path.is_file():
            continue
        name = path.name.lower()
        if name.endswith(SARIF_FILE_SUFFIXES):
            files.append(path)
    return sorted(files)


def import_sarif_tree(root: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    files = find_sarif_files(root)
    per_file: list[dict[str, Any]] = []
    for path in files:
        imported = import_sarif_file(path, source_root=root)
        findings.extend(imported)
        per_file.append(
            {
                "path": normalize_finding_path(path, source_root=root),
                "imported_findings": len(imported),
            }
        )
    return findings, {
        "file_count": len(files),
        "imported_findings": len(findings),
        "files": per_file,
    }


def _sarif_rule_for(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.recommendation or finding.description},
        "properties": {
            "category": finding.category,
            "source": finding.source,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "references": finding.references,
        },
    }


def _sarif_location_for(finding: Finding) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {
            "uri": finding.path or "scanforge://project",
            "uriBaseId": "%SRCROOT%",
        }
    }
    if finding.line:
        physical["region"] = {"startLine": finding.line}
    return {"physicalLocation": physical}


def build_sarif_report(
    findings: list[Finding],
    *,
    root_uri: str = "",
    invocation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized = normalize_findings(list(findings))
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in normalized:
        rules.setdefault(finding.rule_id, _sarif_rule_for(finding))
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": SARIF_LEVEL_FROM_SEVERITY.get(finding.severity, "note"),
            "message": {"text": finding.description or finding.title},
            "locations": [_sarif_location_for(finding)],
            "partialFingerprints": {"scanforgeFingerprint": finding.fingerprint},
            "properties": {
                "scanforgeCategory": finding.category,
                "scanforgeSeverity": finding.severity,
                "source": finding.source,
                "confidence": finding.confidence,
                "lifecycleState": finding.lifecycle_state,
                "reviewState": finding.review_state,
                "references": finding.references,
            },
        }
        if finding.evidence:
            result["properties"]["evidence"] = finding.evidence
        if finding.trace:
            result["properties"]["trace"] = finding.trace
        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": PROJECT_NAME,
                "version": PROJECT_VERSION,
                "informationUri": "https://github.com/",
                "rules": sorted(rules.values(), key=lambda item: item["id"]),
            }
        },
        "results": results,
    }
    if root_uri:
        run["originalUriBaseIds"] = {
            "%SRCROOT%": {
                "uri": root_uri if root_uri.endswith("/") else f"{root_uri}/",
            }
        }
    if invocation:
        run["invocations"] = [invocation]
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def write_sarif_report(
    findings: list[Finding],
    output_path: Path,
    *,
    root_uri: str = "",
    invocation: dict[str, Any] | None = None,
) -> Path:
    payload = build_sarif_report(findings, root_uri=root_uri, invocation=invocation)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path


def normalized_finding_dicts(findings: list[Finding], *, source_root: Path | None = None) -> list[dict[str, Any]]:
    return [asdict(item) for item in normalize_findings(findings, source_root=source_root)]
