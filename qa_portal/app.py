from __future__ import annotations

from dataclasses import asdict
import os
import subprocess
import sys
import uuid
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .analysis import is_archive
from .ai_review import ai_backend_status
from .hardware import detect_host_hardware, recommended_worker_processes
from .i18n import (
    DEFAULT_LANGUAGE,
    LANG_COOKIE_NAME,
    SUPPORTED_LANGUAGES,
    build_ui_i18n,
    normalize_language,
    translate,
    translate_value,
)
from .knowledge_base import (
    knowledge_base_status,
    start_background_knowledge_base_sync,
    start_knowledge_base_scheduler,
    stop_knowledge_base_scheduler,
)
from .config import AUTOSTART_WORKER, STATIC_DIR, TEMPLATES_DIR, UPLOAD_DIR
from .models import JobOptions, JobRecord
from .presets import list_presets, normalize_preset_name, preset_options
from .storage import JobStore, default_steps
from .tooling import detect_toolchain


app = FastAPI(title="ScanForge", version="0.2.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
store = JobStore()


def resolve_language(request: Request) -> str:
    requested = request.query_params.get("lang")
    if requested in SUPPORTED_LANGUAGES:
        return requested
    cookie_value = request.cookies.get(LANG_COOKIE_NAME)
    if cookie_value in SUPPORTED_LANGUAGES:
        return cookie_value
    return DEFAULT_LANGUAGE


def build_lang_switch_urls(request: Request) -> dict[str, str]:
    return {
        code: str(request.url.include_query_params(lang=code))
        for code in SUPPORTED_LANGUAGES
    }


def build_modes(language: str) -> list[tuple[str, str]]:
    return [
        ("full_scan", translate_value(language, "mode", "full_scan")),
        ("fuzz_single", translate_value(language, "mode", "fuzz_single")),
        ("fuzz_project", translate_value(language, "mode", "fuzz_project")),
    ]


def template_context(request: Request, data: dict) -> dict:
    language = resolve_language(request)
    return {
        **data,
        "lang": language,
        "tr": lambda text, **kwargs: translate(language, text, **kwargs),
        "label": lambda category, value: translate_value(language, category, value),
        "lang_switch_urls": build_lang_switch_urls(request),
        "ui_i18n": build_ui_i18n(language),
    }


@app.middleware("http")
async def persist_language_cookie(request: Request, call_next):
    response = await call_next(request)
    requested = request.query_params.get("lang")
    if requested in SUPPORTED_LANGUAGES:
        response.set_cookie(
            LANG_COOKIE_NAME,
            requested,
            max_age=365 * 24 * 60 * 60,
            samesite="lax",
        )
    return response


@app.on_event("startup")
async def app_startup() -> None:
    start_knowledge_base_scheduler()


@app.on_event("shutdown")
async def app_shutdown() -> None:
    stop_knowledge_base_scheduler()


def worker_mode() -> str:
    return "autostart-subprocess" if AUTOSTART_WORKER else "external-worker"


def parse_checkbox(value: str | None) -> bool:
    return value in {"on", "true", "1", "yes"}


def normalize_project_key(filename: str) -> str:
    normalized = Path(filename.strip() or "upload").name.casefold()
    archive_suffixes = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar", ".gz", ".bz2", ".xz")
    for suffix in archive_suffixes:
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            return normalized[: -len(suffix)]
    return normalized


def related_jobs_for_project(project_key: str, *, exclude_job_ids: set[str] | None = None) -> list[JobRecord]:
    excluded = exclude_job_ids or set()
    related = [
        job for job in store.list()
        if job.id not in excluded
        and (job.metadata.get("project_key") or normalize_project_key(job.original_filename)) == project_key
    ]
    return sorted(related, key=lambda job: job.created_at, reverse=True)


def latest_baseline_for(project_key: str, *, exclude_job_ids: set[str] | None = None) -> JobRecord | None:
    candidates = [
        job
        for job in related_jobs_for_project(project_key, exclude_job_ids=exclude_job_ids)
        if Path(job.upload_path).exists()
    ]
    return candidates[0] if candidates else None


def repeat_submission_catalog(jobs: list[JobRecord]) -> list[dict[str, str]]:
    seen: set[str] = set()
    catalog: list[dict[str, str]] = []
    for job in sorted(jobs, key=lambda item: item.created_at, reverse=True):
        project_key = job.metadata.get("project_key") or normalize_project_key(job.original_filename)
        if project_key in seen:
            continue
        seen.add(project_key)
        catalog.append(
            {
                "project_key": project_key,
                "original_filename": job.original_filename,
            }
        )
    return catalog


def dashboard_overview(jobs: list[JobRecord]) -> dict[str, int]:
    return {
        "total_jobs": len(jobs),
        "running_jobs": sum(1 for job in jobs if job.status == "running"),
        "paused_jobs": sum(1 for job in jobs if job.status == "paused"),
        "queued_jobs": sum(1 for job in jobs if job.status == "queued"),
        "completed_jobs": sum(1 for job in jobs if job.status == "completed"),
        "failed_jobs": sum(1 for job in jobs if job.status == "failed"),
        "risky_jobs": sum(
            1 for job in jobs if any(finding.severity in {"critical", "high"} for finding in job.findings)
        ),
    }


def start_background_job(job_id: str) -> None:
    del job_id
    if not AUTOSTART_WORKER:
        return
    env = os.environ.copy()
    subprocess.Popen(
        [sys.executable, "-m", "qa_portal.worker", "once"],
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )


def sanitize_return_path(target: str | None) -> str:
    if not target:
        return "/"
    if not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


def sort_findings(job: JobRecord):
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return sorted(
        job.findings,
        key=lambda item: (severity_order.get(item.severity, 0), item.category, item.path, item.line or 0),
        reverse=True,
    )


def serialize_job(job: JobRecord, *, include_findings: bool = False) -> dict:
    payload = job.to_dict()
    payload["selected_checks"] = job.options.enabled_checks(job.mode)
    payload["report_preview_url"] = f"/jobs/{job.id}/artifacts/{job.html_report}" if job.html_report else None
    payload["can_rerun"] = Path(job.upload_path).exists()
    payload["queue_controls_enabled"] = job.status in {"queued", "paused"}
    if include_findings:
        payload["sorted_findings"] = [finding.__dict__ for finding in sort_findings(job)]
    return payload


def filter_jobs(
    jobs: list[JobRecord],
    *,
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
) -> list[JobRecord]:
    normalized_query = query.strip().casefold()
    filtered: list[JobRecord] = []
    for job in jobs:
        if normalized_query:
            haystack = " ".join([job.id, job.name, job.original_filename]).casefold()
            if normalized_query not in haystack:
                continue
        if status != "all" and job.status != status:
            continue
        if mode != "all" and job.mode != mode:
            continue
        if preset != "all" and job.options.preset != preset:
            continue
        filtered.append(job)
    return filtered


def queue_ordered_jobs(jobs: list[JobRecord]) -> list[JobRecord]:
    status_rank = {
        "running": 0,
        "queued": 1,
        "paused": 2,
        "failed": 3,
        "completed": 4,
        "cancelled": 5,
    }
    return sorted(
        jobs,
        key=lambda job: (
            status_rank.get(job.status, 99),
            job.queue_position if job.queue_position > 0 else 10**9,
            job.created_at,
        ),
    )


def build_job_options(
    *,
    preset: str,
    mode: str,
    retest_scope: str | None,
    run_functionality: str | None,
    run_security: str | None,
    run_style: str | None,
    run_quality: str | None,
    run_fuzzing: str | None,
    fuzz_duration_seconds: int,
    max_report_findings: int,
) -> JobOptions:
    normalized_preset = normalize_preset_name(preset)
    options = preset_options(normalized_preset, mode)
    options.preset = normalized_preset
    if retest_scope in {"full_project", "changes_only"}:
        options.retest_scope = retest_scope  # type: ignore[assignment]
    if run_functionality is not None:
        options.run_functionality = parse_checkbox(run_functionality)
    if run_security is not None:
        options.run_security = parse_checkbox(run_security)
    if run_style is not None:
        options.run_style = parse_checkbox(run_style)
    if run_quality is not None:
        options.run_quality = parse_checkbox(run_quality)
    if run_fuzzing is not None or mode in {"fuzz_single", "fuzz_project"}:
        options.run_fuzzing = parse_checkbox(run_fuzzing) or mode in {"fuzz_single", "fuzz_project"}
    options.fuzz_duration_seconds = max(10, min(fuzz_duration_seconds, 3600))
    options.max_report_findings = max(20, min(max_report_findings, 1000))
    return options


def create_job_record(
    *,
    name: str,
    mode: str,
    original_name: str,
    upload_path: Path,
    options: JobOptions,
    metadata: dict | None = None,
) -> JobRecord:
    job_id = uuid.uuid4().hex[:12]
    job_dir = store.job_dir(job_id)
    workspace_path = job_dir / "workspace"
    output_dir = job_dir / "reports"
    workspace_path.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_type = "archive" if is_archive(upload_path) else "single_file"
    job = JobRecord(
        id=job_id,
        name=name.strip() or "Untitled job",
        mode=mode,  # type: ignore[arg-type]
        input_type=input_type,  # type: ignore[arg-type]
        original_filename=original_name,
        upload_path=str(upload_path),
        workspace_path=str(workspace_path),
        output_dir=str(output_dir),
        queue_position=store.next_queue_position(),
        options=options,
        steps=default_steps(mode, options),
    )
    job.metadata.update(
        {
            "project_key": normalize_project_key(original_name),
            "retest_scope": options.retest_scope,
            "repeat_submission": False,
        }
    )
    if metadata:
        job.metadata.update(metadata)
    return job


def clone_job(
    job: JobRecord,
    *,
    retest_scope: str = "full_project",
    baseline_job: JobRecord | None = None,
    ui_language: str | None = None,
) -> JobRecord:
    clone_options = JobOptions(**asdict(job.options))
    clone_options.retest_scope = retest_scope  # type: ignore[assignment]
    baseline = baseline_job or job
    cloned = create_job_record(
        name=f"{job.name} (rerun)",
        mode=job.mode,
        original_name=job.original_filename,
        upload_path=Path(job.upload_path),
        options=clone_options,
        metadata={
            "project_key": job.metadata.get("project_key", normalize_project_key(job.original_filename)),
            "retest_scope": retest_scope,
            "repeat_submission": True,
            "baseline_job_id": baseline.id,
            "baseline_job_name": baseline.name,
            "baseline_created_at": baseline.created_at,
            "ui_language": normalize_language(ui_language or str(job.metadata.get("ui_language", DEFAULT_LANGUAGE))),
        },
    )
    cloned.metadata["rerun_of"] = job.id
    return cloned


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def index(
    request: Request,
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
):
    language = resolve_language(request)
    all_jobs = store.list()
    jobs = filter_jobs(all_jobs, query=query, status=status, mode=mode, preset=preset)
    tools = detect_toolchain()
    ai_backend = ai_backend_status()
    kb_status = knowledge_base_status()
    hardware = detect_host_hardware()
    known_repeat_projects = repeat_submission_catalog(all_jobs)
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context(request, {
            "jobs": jobs,
            "queue_jobs": queue_ordered_jobs(jobs),
            "all_jobs_count": len(all_jobs),
            "modes": build_modes(language),
            "overview": dashboard_overview(jobs),
            "tools": tools,
            "ai_backend": ai_backend,
            "knowledge_base": kb_status,
            "hardware": hardware.to_dict(),
            "recommended_workers": recommended_worker_processes(hardware),
            "worker_mode": worker_mode(),
            "presets": list_presets(language),
            "known_repeat_projects": known_repeat_projects,
            "filters": {
                "query": query,
                "status": status,
                "mode": mode,
                "preset": preset,
            },
        }),
    )


@app.post("/jobs")
async def create_job(
    request: Request,
    name: str = Form(""),
    mode: str = Form(...),
    preset: str = Form("balanced"),
    retest_scope: str | None = Form(None),
    run_functionality: str | None = Form(None),
    run_security: str | None = Form(None),
    run_style: str | None = Form(None),
    run_quality: str | None = Form(None),
    run_fuzzing: str | None = Form(None),
    fuzz_duration_seconds: int = Form(60),
    max_report_findings: int = Form(200),
    upload: list[UploadFile] = File(...),
):
    if mode not in {"full_scan", "fuzz_single", "fuzz_project"}:
        raise HTTPException(status_code=400, detail="Unsupported job mode.")

    ui_language = resolve_language(request)
    options = build_job_options(
        preset=preset,
        mode=mode,
        retest_scope=retest_scope,
        run_functionality=run_functionality,
        run_security=run_security,
        run_style=run_style,
        run_quality=run_quality,
        run_fuzzing=run_fuzzing,
        fuzz_duration_seconds=fuzz_duration_seconds,
        max_report_findings=max_report_findings,
    )
    if not options.enabled_checks(mode):
        raise HTTPException(status_code=400, detail="Select at least one analysis type.")

    uploads = [item for item in upload if item.filename]
    if not uploads:
        raise HTTPException(status_code=400, detail="Upload at least one project archive or source file.")

    created_jobs: list[JobRecord] = []
    existing_jobs = store.list()
    for index, item in enumerate(uploads, start=1):
        original_name = Path(item.filename or "upload.bin").name
        upload_path = UPLOAD_DIR / f"{uuid.uuid4().hex[:12]}_{original_name}"
        upload_path.parent.mkdir(parents=True, exist_ok=True)

        with upload_path.open("wb") as handle:
            while True:
                chunk = await item.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)

        job_name = name
        if len(uploads) > 1:
            job_name = f"{name.strip() or 'Batch job'} #{index}: {original_name}"
        project_key = normalize_project_key(original_name)
        baseline = latest_baseline_for(project_key, exclude_job_ids={job.id for job in created_jobs})
        job_retest_scope = options.retest_scope if baseline else "full_project"
        job_options = JobOptions(**asdict(options))
        job_options.retest_scope = job_retest_scope  # type: ignore[assignment]
        job = create_job_record(
            name=job_name,
            mode=mode,
            original_name=original_name,
            upload_path=upload_path,
            options=job_options,
            metadata={
                "project_key": project_key,
                "retest_scope": job_retest_scope,
                "repeat_submission": baseline is not None,
                "baseline_job_id": baseline.id if baseline else None,
                "baseline_job_name": baseline.name if baseline else None,
                "baseline_created_at": baseline.created_at if baseline else None,
                "ui_language": ui_language,
                "repeat_detected_from_history": any(
                    (job.metadata.get("project_key") or normalize_project_key(job.original_filename)) == project_key
                    for job in existing_jobs
                ),
            },
        )
        store.save(job)
        created_jobs.append(job)

    for job in created_jobs:
        start_background_job(job.id)

    if len(created_jobs) == 1:
        return RedirectResponse(url=f"/jobs/{created_jobs[0].id}", status_code=303)
    return RedirectResponse(url="/", status_code=303)


@app.get("/jobs/{job_id}/rerun")
async def rerun_job_options(request: Request, job_id: str):
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    related_jobs = related_jobs_for_project(
        job.metadata.get("project_key", normalize_project_key(job.original_filename)),
        exclude_job_ids={job.id},
    )
    return templates.TemplateResponse(
        request,
        "retest.html",
        template_context(request, {
            "job": job,
            "baseline_job": job,
            "related_jobs": related_jobs[:5],
        }),
    )


@app.post("/jobs/{job_id}/rerun")
async def rerun_job(request: Request, job_id: str, retest_scope: str = Form("full_project")):
    try:
        original = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    upload_path = Path(original.upload_path)
    if not upload_path.exists():
        raise HTTPException(status_code=400, detail="Original upload is no longer available.")

    normalized_scope = retest_scope if retest_scope in {"full_project", "changes_only"} else "full_project"
    cloned = clone_job(
        original,
        retest_scope=normalized_scope,
        baseline_job=original,
        ui_language=resolve_language(request),
    )
    store.save(cloned)
    start_background_job(cloned.id)
    return RedirectResponse(url=f"/jobs/{cloned.id}", status_code=303)


@app.get("/jobs/{job_id}")
async def job_detail(request: Request, job_id: str):
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    report_preview_url = f"/jobs/{job.id}/artifacts/{job.html_report}" if job.html_report else None
    return templates.TemplateResponse(
        request,
        "job.html",
        template_context(request, {
            "job": job,
            "findings": sort_findings(job),
            "report_preview_url": report_preview_url,
            "selected_checks": job.options.enabled_checks(job.mode),
            "ai_backend": ai_backend_status(),
            "worker_mode": worker_mode(),
            "queue_jobs": queue_ordered_jobs(store.list()),
            "related_jobs": related_jobs_for_project(
                job.metadata.get("project_key", normalize_project_key(job.original_filename)),
                exclude_job_ids={job.id},
            )[:5],
        }),
    )


@app.get("/api/jobs/{job_id}")
async def job_api(job_id: str):
    try:
        return serialize_job(store.load(job_id), include_findings=True)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc


@app.get("/api/jobs")
async def jobs_api(
    query: str = "",
    status: str = "all",
    mode: str = "all",
    preset: str = "all",
):
    jobs = filter_jobs(store.list(), query=query, status=status, mode=mode, preset=preset)
    return [serialize_job(job) for job in jobs]


@app.get("/api/tools")
async def tools_api():
    return detect_toolchain()


@app.get("/api/knowledge-base")
async def knowledge_base_api():
    return knowledge_base_status()


@app.post("/knowledge-base/sync")
async def knowledge_base_sync_now(next_url: str = Form("/")):
    start_background_knowledge_base_sync(force=True)
    return RedirectResponse(url=sanitize_return_path(next_url), status_code=303)


@app.post("/api/knowledge-base/sync")
async def knowledge_base_sync_now_api():
    started = start_background_knowledge_base_sync(force=True)
    return {
        "started": started,
        "knowledge_base": knowledge_base_status(),
    }


@app.get("/api/system")
async def system_api():
    hardware = detect_host_hardware()
    return {
        "tools": detect_toolchain(),
        "ai_backend": ai_backend_status(),
        "knowledge_base": knowledge_base_status(),
        "hardware": hardware.to_dict(),
        "recommended_worker_processes": recommended_worker_processes(hardware),
        "worker_mode": worker_mode(),
        "queued_jobs": sum(1 for job in store.list() if job.status == "queued"),
        "paused_jobs": sum(1 for job in store.list() if job.status == "paused"),
    }


@app.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    try:
        job = store.request_cancel(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    if job.status == "cancelled":
        return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.post("/jobs/{job_id}/pause")
async def pause_job(job_id: str):
    try:
        store.request_pause(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.post("/jobs/{job_id}/resume")
async def resume_job(job_id: str):
    try:
        job = store.resume_job(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc
    if job.status == "queued":
        start_background_job(job.id)
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.post("/jobs/{job_id}/queue/up")
async def move_job_up(job_id: str):
    try:
        store.move_in_queue(job_id, -1)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/jobs/{job_id}/queue/down")
async def move_job_down(job_id: str):
    try:
        store.move_in_queue(job_id, 1)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/jobs/{job_id}/queue/reposition")
async def reposition_job_in_queue(
    job_id: str,
    target_job_id: str = Body(...),
    placement: str = Body("before"),
):
    if placement not in {"before", "after"}:
        raise HTTPException(status_code=400, detail="Placement must be 'before' or 'after'.")
    try:
        job = store.reposition_in_queue(job_id, target_job_id, place_after=placement == "after")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found or not movable in queue.") from exc
    return serialize_job(job)


@app.get("/jobs/{job_id}/artifacts/{filename}")
async def download_artifact(job_id: str, filename: str):
    try:
        job = store.load(job_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc

    artifact_path = Path(job.output_dir) / filename
    if not artifact_path.exists() or artifact_path.parent != Path(job.output_dir):
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return FileResponse(str(artifact_path), filename=artifact_path.name)
