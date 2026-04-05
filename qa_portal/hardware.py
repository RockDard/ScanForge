from __future__ import annotations

import math
import os
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import RESOURCE_TARGET_UTILIZATION_PERCENT


_CACHE: dict[str, tuple[float, "HostHardwareProfile"]] = {}


@dataclass
class GPUDevice:
    index: int
    name: str
    memory_total_mb: int = 0
    utilization_percent: int | None = None
    driver: str = ""


@dataclass
class HostHardwareProfile:
    cpu_threads_total: int
    cpu_threads_target: int
    memory_total_mb: int
    memory_target_mb: int
    utilization_target_percent: int
    gpus: list[GPUDevice] = field(default_factory=list)
    nvidia_smi_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["gpu_count"] = len(self.gpus)
        return payload


@dataclass
class AdaptiveExecutionPlan:
    running_jobs: int
    cpu_threads_for_job: int
    memory_mb_for_job: int
    build_parallelism: int
    test_parallelism: int
    clang_tidy_workers: int
    cppcheck_jobs: int
    file_scan_workers: int
    suggested_worker_processes: int
    assigned_gpu_ids: list[int] = field(default_factory=list)
    visible_gpu_ids: list[int] = field(default_factory=list)
    gpu_strategy: str = "cpu-only"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clone_profile(profile: HostHardwareProfile) -> HostHardwareProfile:
    return HostHardwareProfile(
        cpu_threads_total=profile.cpu_threads_total,
        cpu_threads_target=profile.cpu_threads_target,
        memory_total_mb=profile.memory_total_mb,
        memory_target_mb=profile.memory_target_mb,
        utilization_target_percent=profile.utilization_target_percent,
        gpus=[
            GPUDevice(
                index=item.index,
                name=item.name,
                memory_total_mb=item.memory_total_mb,
                utilization_percent=item.utilization_percent,
                driver=item.driver,
            )
            for item in profile.gpus
        ],
        nvidia_smi_path=profile.nvidia_smi_path,
    )


def _detect_total_memory_mb() -> int:
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if not line.startswith("MemTotal:"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return max(1, int(parts[1]) // 1024)
    if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names and "SC_PHYS_PAGES" in os.sysconf_names:
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            page_count = int(os.sysconf("SC_PHYS_PAGES"))
            return max(1, (page_size * page_count) // (1024 * 1024))
        except (OSError, ValueError):
            pass
    return 1024


def _detect_nvidia_gpus() -> tuple[list[GPUDevice], str | None]:
    nvidia_smi = shutil_which("nvidia-smi")
    if not nvidia_smi:
        return [], None
    command = [
        nvidia_smi,
        "--query-gpu=index,name,memory.total,utilization.gpu,driver_version",
        "--format=csv,noheader,nounits",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return [], nvidia_smi
    if completed.returncode != 0:
        return [], nvidia_smi
    devices: list[GPUDevice] = []
    for line in completed.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 5:
            continue
        index_text, name, memory_text, utilization_text, driver = parts[:5]
        if not index_text.isdigit():
            continue
        devices.append(
            GPUDevice(
                index=int(index_text),
                name=name,
                memory_total_mb=int(memory_text) if memory_text.isdigit() else 0,
                utilization_percent=int(utilization_text) if utilization_text.isdigit() else None,
                driver=driver,
            )
        )
    return devices, nvidia_smi


def shutil_which(name: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(folder) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def detect_host_hardware() -> HostHardwareProfile:
    cached = _CACHE.get("host")
    now = time.monotonic()
    if cached and now - cached[0] < 10:
        return _clone_profile(cached[1])
    total_threads = max(1, os.cpu_count() or 1)
    target_threads = max(1, math.floor(total_threads * RESOURCE_TARGET_UTILIZATION_PERCENT / 100))
    total_memory_mb = _detect_total_memory_mb()
    target_memory_mb = max(512, math.floor(total_memory_mb * RESOURCE_TARGET_UTILIZATION_PERCENT / 100))
    gpus, nvidia_smi_path = _detect_nvidia_gpus()
    profile = HostHardwareProfile(
        cpu_threads_total=total_threads,
        cpu_threads_target=target_threads,
        memory_total_mb=total_memory_mb,
        memory_target_mb=target_memory_mb,
        utilization_target_percent=RESOURCE_TARGET_UTILIZATION_PERCENT,
        gpus=gpus,
        nvidia_smi_path=nvidia_smi_path,
    )
    _CACHE["host"] = (now, _clone_profile(profile))
    return profile


def recommended_worker_processes(profile: HostHardwareProfile) -> int:
    if profile.gpus:
        gpu_parallel = max(1, len(profile.gpus))
        cpu_parallel = max(1, profile.cpu_threads_target // 6)
        return max(1, min(profile.cpu_threads_target, max(gpu_parallel, cpu_parallel)))
    return max(1, min(profile.cpu_threads_target, max(1, profile.cpu_threads_target // 6)))


def assign_gpu_ids(job_id: str, running_job_ids: list[str], profile: HostHardwareProfile) -> list[int]:
    if not profile.gpus:
        return []
    sorted_gpu_ids = [gpu.index for gpu in sorted(profile.gpus, key=lambda item: item.index)]
    sorted_jobs = sorted(set(running_job_ids))
    if len(sorted_jobs) <= 1:
        return sorted_gpu_ids
    try:
        job_index = sorted_jobs.index(job_id)
    except ValueError:
        job_index = 0
    return [sorted_gpu_ids[job_index % len(sorted_gpu_ids)]]


def build_execution_plan(
    *,
    job_id: str,
    running_job_ids: list[str],
    profile: HostHardwareProfile | None = None,
) -> AdaptiveExecutionPlan:
    profile = profile or detect_host_hardware()
    running_jobs = max(1, len(running_job_ids))
    cpu_threads_for_job = max(1, profile.cpu_threads_target // running_jobs)
    memory_mb_for_job = max(512, profile.memory_target_mb // running_jobs)
    assigned_gpu_ids = assign_gpu_ids(job_id, running_job_ids, profile)
    visible_gpu_ids = [gpu.index for gpu in sorted(profile.gpus, key=lambda item: item.index)]
    gpu_strategy = "cpu-only"
    if visible_gpu_ids and len(assigned_gpu_ids) == len(visible_gpu_ids):
        gpu_strategy = "single-job-all-gpus"
    elif assigned_gpu_ids:
        gpu_strategy = "distributed-single-gpu-per-job"
    return AdaptiveExecutionPlan(
        running_jobs=running_jobs,
        cpu_threads_for_job=cpu_threads_for_job,
        memory_mb_for_job=memory_mb_for_job,
        build_parallelism=max(1, cpu_threads_for_job),
        test_parallelism=max(1, min(cpu_threads_for_job, 32)),
        clang_tidy_workers=max(1, min(cpu_threads_for_job, 8)),
        cppcheck_jobs=max(1, min(cpu_threads_for_job, 16)),
        file_scan_workers=max(1, min(cpu_threads_for_job, 12)),
        suggested_worker_processes=recommended_worker_processes(profile),
        assigned_gpu_ids=assigned_gpu_ids,
        visible_gpu_ids=visible_gpu_ids,
        gpu_strategy=gpu_strategy,
    )


def build_runtime_env(plan: AdaptiveExecutionPlan | None) -> dict[str, str]:
    env = {"QT_QPA_PLATFORM": "offscreen"}
    if not plan:
        return env
    env["QA_PORTAL_CPU_THREADS"] = str(plan.cpu_threads_for_job)
    env["QA_PORTAL_MEMORY_MB"] = str(plan.memory_mb_for_job)
    env["QA_PORTAL_GPU_STRATEGY"] = plan.gpu_strategy
    if plan.assigned_gpu_ids:
        gpu_csv = ",".join(str(item) for item in plan.assigned_gpu_ids)
        env["CUDA_VISIBLE_DEVICES"] = gpu_csv
        env["NVIDIA_VISIBLE_DEVICES"] = gpu_csv
    return env
