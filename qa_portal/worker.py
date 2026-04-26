from __future__ import annotations

import argparse
import multiprocessing
import os
import socket
import sys
import time

from .config import STALE_RUNNING_SECONDS, WORKER_POLL_SECONDS, WORKER_PROCESSES
from .hardware import detect_host_hardware, recommended_worker_processes
from .pipeline import run_job
from .storage import JobContext, JobStore


def worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def process_one_job(store: JobStore) -> bool:
    store.recover_stale_running(STALE_RUNNING_SECONDS)
    claimed = store.try_claim(worker_id())
    if claimed is None:
        return False
    run_job(JobContext(store, claimed.id))
    return True


def run_once() -> int:
    store = JobStore()
    return 0 if process_one_job(store) else 0


def run_loop(poll_seconds: int = WORKER_POLL_SECONDS) -> int:
    store = JobStore()
    while True:
        worked = process_one_job(store)
        if not worked:
            time.sleep(max(1, poll_seconds))


def resolve_worker_processes(raw: str = WORKER_PROCESSES) -> int:
    text = (raw or "auto").strip().lower()
    if text == "auto":
        return recommended_worker_processes(detect_host_hardware())
    try:
        return max(1, int(text))
    except ValueError:
        return 1


def run_pool(processes: int, poll_seconds: int = WORKER_POLL_SECONDS) -> int:
    if processes <= 1:
        return run_loop(poll_seconds=poll_seconds)
    workers = [
        multiprocessing.Process(target=run_loop, args=(poll_seconds,), name=f"qa-worker-{index + 1}")
        for index in range(processes)
    ]
    for worker in workers:
        worker.start()
    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown path
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
        for worker in workers:
            worker.join(timeout=5)
        return 130
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ScanForge worker")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("once", help="Claim and process a single queued job if one exists.")

    loop_parser = subparsers.add_parser("loop", help="Continuously poll for queued jobs.")
    loop_parser.add_argument("--poll-seconds", type=int, default=WORKER_POLL_SECONDS)

    pool_parser = subparsers.add_parser("pool", help="Run a worker pool sized for the current host.")
    pool_parser.add_argument("--poll-seconds", type=int, default=WORKER_POLL_SECONDS)
    pool_parser.add_argument("--processes", default=WORKER_PROCESSES)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "once":
        return run_once()
    if args.command == "loop":
        return run_loop(poll_seconds=args.poll_seconds)
    if args.command == "pool":
        return run_pool(processes=resolve_worker_processes(args.processes), poll_seconds=args.poll_seconds)
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
