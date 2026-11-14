"""Unit tests for the in-memory job registry (backend/jobs.py)."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import jobs  # noqa: E402


def test_lifecycle_running_to_done():
    j = jobs.create(total=3)
    assert jobs.get(j.id) is j

    snap = j.snapshot()
    assert snap["status"] == "running"
    assert snap["total"] == 3 and snap["done"] == 0 and snap["warnings"] == 0
    assert snap["result"] is None

    j.tick("sigA -> defX")
    j.tick("sigB -> defY", degraded=True)
    snap = j.snapshot()
    assert snap["done"] == 2
    assert snap["warnings"] == 1
    assert snap["current_pair"] == "sigB -> defY"
    assert snap["result"] is None  # not surfaced until done

    j.finish({"ok": True})
    snap = j.snapshot()
    assert snap["status"] == "done"
    assert snap["result"] == {"ok": True}


def test_fail_carries_message():
    j = jobs.create(total=1)
    j.fail("boom")
    snap = j.snapshot()
    assert snap["status"] == "failed"
    assert snap["error"] == "boom"
    assert snap["result"] is None


def test_missing_job_is_none():
    assert jobs.get("does-not-exist") is None


def test_stale_jobs_are_collected():
    old = jobs.create(total=1)
    old.updated = time.time() - jobs._TTL_SECONDS - 10
    jobs.create(total=1)  # any create() triggers a GC pass
    assert jobs.get(old.id) is None
