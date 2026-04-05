from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from pathlib import Path
import tempfile
from typing import Callable, Iterator

import fcntl

from .config import JOBS_DIR
from .models import Artifact, JobOptions, JobRecord, StepProgress, utc_now


Mutator = Callable[[JobRecord], None]


class JobStore:
    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or JOBS_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def job_dir(self, job_id: str) -> Path:
        return self.base_dir / job_id

    def job_file(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "job.json"

    def job_lock_file(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "job.lock"

    @contextmanager
    def _job_lock(self, job_id: str) -> Iterator[None]:
        folder = self.job_dir(job_id)
        folder.mkdir(parents=True, exist_ok=True)
        lock_path = self.job_lock_file(job_id)
        with lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _save_unlocked(self, job: JobRecord) -> None:
        job.updated_at = utc_now()
        folder = self.job_dir(job.id)
        folder.mkdir(parents=True, exist_ok=True)
        destination = self.job_file(job.id)
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            dir=str(folder),
            encoding="utf-8",
        ) as handle:
            json.dump(job.to_dict(), handle, indent=2, ensure_ascii=False)
            temp_name = handle.name
        Path(temp_name).replace(destination)

    def _load_unlocked(self, job_id: str) -> JobRecord:
        return JobRecord.from_dict(
            json.loads(self.job_file(job_id).read_text(encoding="utf-8"))
        )

    def save(self, job: JobRecord) -> None:
        with self._lock:
            with self._job_lock(job.id):
                self._save_unlocked(job)

    def load(self, job_id: str) -> JobRecord:
        with self._lock:
            with self._job_lock(job_id):
                return self._load_unlocked(job_id)

    def list(self) -> list[JobRecord]:
        jobs: list[JobRecord] = []
        with self._lock:
            for job_file in sorted(self.base_dir.glob("*/job.json"), reverse=True):
                jobs.append(
                    JobRecord.from_dict(json.loads(job_file.read_text(encoding="utf-8")))
                )
        jobs.sort(key=lambda item: item.created_at, reverse=True)
        return jobs

    def next_queue_position(self) -> int:
        positions = [job.queue_position for job in self.list() if job.queue_position > 0]
        return (max(positions) + 1) if positions else 1

    def _queue_candidates(self) -> list[JobRecord]:
        candidates = [job for job in self.list() if job.status in {"queued", "paused"}]
        return sorted(candidates, key=lambda job: (job.queue_position or 10**9, job.created_at, job.id))

    def try_claim(self, worker_id: str) -> JobRecord | None:
        for candidate in self._queue_candidates():
            if candidate.status != "queued":
                continue

            claimed: JobRecord | None = None

            def mutator(job: JobRecord) -> None:
                nonlocal claimed
                if job.status != "queued":
                    return
                job.status = "running"
                job.current_step = "Worker claimed job"
                job.progress = max(job.progress, 1)
                job.metadata["worker_id"] = worker_id
                job.metadata["claimed_at"] = utc_now()
                claimed = job

            current = self.mutate(candidate.id, mutator)
            if claimed is not None:
                return current
        return None

    def normalize_queue(self) -> None:
        ordered = self._queue_candidates()
        for index, job in enumerate(ordered, start=1):
            if job.queue_position == index:
                continue
            self.mutate(job.id, lambda current, pos=index: setattr(current, "queue_position", pos))

    def mutate(self, job_id: str, mutator: Mutator) -> JobRecord:
        with self._lock:
            with self._job_lock(job_id):
                job = self._load_unlocked(job_id)
                mutator(job)
                self._save_unlocked(job)
                return job

    def request_cancel(self, job_id: str) -> JobRecord:
        def mutator(job: JobRecord) -> None:
            job.metadata["cancel_requested"] = True
            job.metadata["cancel_requested_at"] = utc_now()
            if job.status in {"queued", "paused"}:
                job.status = "cancelled"
                job.current_step = "Cancelled before execution"
                job.progress = 100
                job.finished_at = utc_now()
                for step in job.steps:
                    if step.status in {"pending", "running"}:
                        step.status = "cancelled"
                        step.progress = 100
                        step.message = "Cancelled before execution."
                        step.finished_at = utc_now()

        return self.mutate(job_id, mutator)

    def request_pause(self, job_id: str) -> JobRecord:
        def mutator(job: JobRecord) -> None:
            if job.status == "queued":
                job.status = "paused"
                job.current_step = "Paused in queue"
                job.metadata["paused_at"] = utc_now()
                job.metadata["pause_requested"] = False
                return
            if job.status == "running":
                job.metadata["pause_requested"] = True
                job.metadata["pause_requested_at"] = utc_now()

        return self.mutate(job_id, mutator)

    def resume_job(self, job_id: str) -> JobRecord:
        def mutator(job: JobRecord) -> None:
            if job.status != "paused":
                return
            job.status = "queued"
            job.current_step = "Queued for resume"
            job.finished_at = None
            job.metadata["pause_requested"] = False
            job.metadata["resumed_at"] = utc_now()
            if job.queue_position <= 0:
                job.queue_position = self.next_queue_position()

        return self.mutate(job_id, mutator)

    def move_in_queue(self, job_id: str, direction: int) -> JobRecord:
        ordered = self._queue_candidates()
        positions = {job.id: index for index, job in enumerate(ordered)}
        if job_id not in positions:
            raise FileNotFoundError(job_id)
        current_index = positions[job_id]
        target_index = current_index + direction
        if target_index < 0 or target_index >= len(ordered):
            return self.load(job_id)

        current_job = ordered[current_index]
        target_job = ordered[target_index]
        current_position = current_job.queue_position
        target_position = target_job.queue_position
        self.mutate(current_job.id, lambda job, pos=target_position: setattr(job, "queue_position", pos))
        self.mutate(target_job.id, lambda job, pos=current_position: setattr(job, "queue_position", pos))
        self.normalize_queue()
        return self.load(job_id)

    def reposition_in_queue(self, job_id: str, target_job_id: str, *, place_after: bool = False) -> JobRecord:
        ordered = self._queue_candidates()
        ordered_ids = [job.id for job in ordered]
        if job_id not in ordered_ids or target_job_id not in ordered_ids:
            raise FileNotFoundError(job_id if job_id not in ordered_ids else target_job_id)
        if job_id == target_job_id:
            return self.load(job_id)

        remaining_ids = [current_id for current_id in ordered_ids if current_id != job_id]
        target_index = remaining_ids.index(target_job_id)
        insert_index = target_index + (1 if place_after else 0)
        remaining_ids.insert(insert_index, job_id)

        for index, current_id in enumerate(remaining_ids, start=1):
            self.mutate(current_id, lambda job, pos=index: setattr(job, "queue_position", pos))
        self.normalize_queue()
        return self.load(job_id)


class JobContext:
    def __init__(self, store: JobStore, job_id: str) -> None:
        self.store = store
        self.job_id = job_id

    def get(self) -> JobRecord:
        return self.store.load(self.job_id)

    def log(self, message: str) -> JobRecord:
        timestamped = f"[{utc_now()}] {message}"
        return self.store.mutate(self.job_id, lambda job: job.logs.append(timestamped))

    def set_status(
        self,
        status: str,
        progress: int | None = None,
        current_step: str | None = None,
        finished: bool = False,
    ) -> JobRecord:
        def mutate(job: JobRecord) -> None:
            job.status = status  # type: ignore[assignment]
            if progress is not None:
                job.progress = progress
            if current_step is not None:
                job.current_step = current_step
            if finished:
                job.finished_at = utc_now()

        return self.store.mutate(self.job_id, mutate)

    def update_step(
        self,
        key: str,
        *,
        status: str,
        progress: int,
        message: str = "",
    ) -> JobRecord:
        def mutate(job: JobRecord) -> None:
            for step in job.steps:
                if step.key != key:
                    continue
                step.status = status  # type: ignore[assignment]
                step.progress = progress
                step.message = message
                if status == "running" and not step.started_at:
                    step.started_at = utc_now()
                if status in {"completed", "failed", "skipped", "cancelled"}:
                    step.finished_at = utc_now()
                break

        return self.store.mutate(self.job_id, mutate)

    def cancel_pending_steps(self, current_key: str | None = None, message: str = "Cancelled.") -> JobRecord:
        def mutate(job: JobRecord) -> None:
            for step in job.steps:
                if current_key and step.key == current_key and step.status == "running":
                    step.status = "cancelled"
                    step.progress = 100
                    step.message = message
                    step.finished_at = utc_now()
                    continue
                if step.status == "pending":
                    step.status = "cancelled"
                    step.progress = 100
                    step.message = message
                    step.finished_at = utc_now()

        return self.store.mutate(self.job_id, mutate)

    def add_findings(self, findings) -> JobRecord:
        return self.store.mutate(self.job_id, lambda job: job.findings.extend(findings))

    def set_metadata(self, metadata: dict) -> JobRecord:
        return self.store.mutate(self.job_id, lambda job: job.metadata.update(metadata))

    def set_summaries(self, summaries: dict) -> JobRecord:
        return self.store.mutate(self.job_id, lambda job: job.summaries.update(summaries))

    def add_artifact(self, artifact: Artifact) -> JobRecord:
        return self.store.mutate(self.job_id, lambda job: job.artifacts.append(artifact))

    def set_report_paths(self, html_report: str | None, pdf_report: str | None) -> JobRecord:
        def mutate(job: JobRecord) -> None:
            job.html_report = html_report
            job.pdf_report = pdf_report

        return self.store.mutate(self.job_id, mutate)

    def is_cancel_requested(self) -> bool:
        return bool(self.get().metadata.get("cancel_requested"))

    def is_pause_requested(self) -> bool:
        return bool(self.get().metadata.get("pause_requested"))


def default_steps(mode: str, options: JobOptions | None = None) -> list[StepProgress]:
    selected = options or JobOptions()
    step_specs = [
        ("ingest", "Ingest upload", True),
        ("discovery", "Discover project", True),
        ("functionality", "Functionality scan", selected.is_enabled("functionality", mode)),
        ("security", "Security scan", selected.is_enabled("security", mode)),
        ("style", "Style scan", selected.is_enabled("style", mode)),
        ("quality", "Quality scan", selected.is_enabled("quality", mode)),
        ("fuzzing", "Fuzzing", selected.is_enabled("fuzzing", mode)),
    ]
    steps: list[StepProgress] = []
    for key, title, enabled in step_specs:
        if enabled:
            steps.append(StepProgress(key=key, title=title))
        else:
            steps.append(
                StepProgress(
                    key=key,
                    title=title,
                    status="skipped",
                    progress=100,
                    message="Disabled in job settings.",
                )
            )
    steps.append(StepProgress(key="reporting", title="Generate reports"))
    return steps
