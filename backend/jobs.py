"""
In-memory job registry for the async LLM analysis path.

The CSV analysis path stays synchronous (it finishes in well under a second).
The LLM path makes one Gemini call per distinct signature-defense pair, which
can run for many minutes, so `POST /api/analyze/async` hands back a job id and
the frontend polls `GET /api/jobs/{id}` until it is done.

Jobs live only in this process. A server restart loses running jobs (the poll
then 404s and the UI asks the user to retry). Finished jobs are dropped an hour
after their last update.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

_TTL_SECONDS = 3600
_lock = threading.RLock()
_jobs: "dict[str, Job]" = {}


@dataclass
class Job:
    id: str
    total: int = 0                 # distinct signature-defense pairs = max Gemini calls
    done: int = 0                  # pairs evaluated so far
    warnings: int = 0             # pairs the evaluator could not score (worst-cased)
    current_pair: str = ""
    status: str = "running"        # running | done | failed
    error: "str | None" = None
    result: Any = None
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)

    def tick(self, pair_label: str, degraded: bool = False) -> None:
        with _lock:
            self.done += 1
            self.current_pair = pair_label
            if degraded:
                self.warnings += 1
            self.updated = time.time()

    def finish(self, result: Any) -> None:
        with _lock:
            self.status = "done"
            self.result = result
            self.updated = time.time()

    def fail(self, message: str) -> None:
        with _lock:
            self.status = "failed"
            self.error = message
            self.updated = time.time()

    def snapshot(self) -> dict:
        with _lock:
            return {
                "job_id": self.id,
                "status": self.status,
                "done": self.done,
                "total": self.total,
                "warnings": self.warnings,
                "current_pair": self.current_pair,
                "error": self.error,
                "result": self.result if self.status == "done" else None,
            }


def _gc_locked() -> None:
    cutoff = time.time() - _TTL_SECONDS
    for k in [k for k, j in _jobs.items() if j.updated < cutoff]:
        del _jobs[k]


def create(total: int) -> Job:
    with _lock:
        _gc_locked()
        job = Job(id=uuid.uuid4().hex[:12], total=int(total))
        _jobs[job.id] = job
        return job


def get(job_id: str) -> "Job | None":
    with _lock:
        _gc_locked()
        return _jobs.get(job_id)
