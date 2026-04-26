from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


Severity = Literal["info", "low", "medium", "high", "critical"]
JobStatus = Literal["queued", "running", "paused", "completed", "failed", "cancelled"]
StepStatus = Literal["pending", "running", "paused", "completed", "failed", "skipped", "cancelled"]
JobMode = Literal["full_scan", "fuzz_single", "fuzz_project"]
InputType = Literal["archive", "single_file"]
CheckKey = Literal["functionality", "security", "style", "quality", "fuzzing"]
RetestScope = Literal["full_project", "changes_only"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    category: str
    severity: Severity
    title: str
    description: str
    path: str = ""
    line: int | None = None
    source: str = ""
    recommendation: str = ""
    references: list[dict[str, Any]] = field(default_factory=list)
    rule_id: str = ""
    confidence: str = "medium"
    evidence: str = ""
    trace: list[dict[str, Any]] = field(default_factory=list)
    fingerprint: str = ""
    lifecycle_state: str = "new"
    review_state: str = "open"
    review_note: str = ""
    muted_until: str | None = None


@dataclass
class StepProgress:
    key: str
    title: str
    status: StepStatus = "pending"
    progress: int = 0
    message: str = ""
    started_at: str | None = None
    finished_at: str | None = None


@dataclass
class Artifact:
    label: str
    filename: str
    kind: str


@dataclass
class JobOptions:
    preset: str = "balanced"
    retest_scope: RetestScope = "full_project"
    run_functionality: bool = True
    run_security: bool = True
    run_style: bool = True
    run_quality: bool = True
    run_fuzzing: bool = False
    fuzz_duration_seconds: int = 60
    max_report_findings: int = 200

    def is_enabled(self, key: CheckKey, mode: JobMode | str) -> bool:
        if key == "fuzzing":
            return self.run_fuzzing or mode in {"fuzz_single", "fuzz_project"}
        return getattr(self, f"run_{key}")

    def enabled_checks(self, mode: JobMode | str) -> list[CheckKey]:
        keys: list[CheckKey] = ["functionality", "security", "style", "quality", "fuzzing"]
        return [key for key in keys if self.is_enabled(key, mode)]


@dataclass
class JobRecord:
    id: str
    name: str
    mode: JobMode
    input_type: InputType
    original_filename: str
    upload_path: str
    workspace_path: str
    output_dir: str
    queue_position: int = 0
    options: JobOptions = field(default_factory=JobOptions)
    status: JobStatus = "queued"
    progress: int = 0
    current_step: str = "Queued"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    extracted_path: str | None = None
    html_report: str | None = None
    pdf_report: str | None = None
    logs: list[str] = field(default_factory=list)
    steps: list[StepProgress] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    summaries: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "JobRecord":
        raw = dict(raw)
        raw["options"] = JobOptions(**raw.get("options", {}))
        raw["steps"] = [StepProgress(**step) for step in raw.get("steps", [])]
        raw["findings"] = [Finding(**finding) for finding in raw.get("findings", [])]
        raw["artifacts"] = [Artifact(**artifact) for artifact in raw.get("artifacts", [])]
        return cls(**raw)
