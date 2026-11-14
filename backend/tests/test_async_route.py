"""
The async LLM route end-to-end, with the Gemini harness stubbed out.

Proves the job flow is wired correctly: 202 + job id, progress ticks bounded by
the distinct-pair count, a result shaped exactly like the synchronous path, and a
CSV download served from the finished job.
"""

import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import ccea_core  # noqa: E402
import llm  # noqa: E402
import main  # noqa: E402

HERE = os.path.dirname(__file__)
SINGLE = os.path.join(HERE, "..", "sample_data", "CCE_single_sample.csv")
NOTEBOOK_BEST_FITNESS = 0.8225830169154041


def _rows(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


@pytest.fixture
def stub_llm(monkeypatch):
    """Replace the Gemini estimator with one that echoes the CSV Reduced_Severity
    and reports progress once per distinct (signature, candidate) pair."""
    rows = ccea_core.validate_and_normalise(_rows(SINGLE))
    rs = {(r["Hash"], r["Candidate_ID"]): float(r["Reduced_Severity"]) for r in rows}
    distinct = {(r["Signature_ID"], r["Candidate_ID"]) for r in rows}

    def fake_get_estimator(force=None, progress_cb=None):
        seen = set()

        def estimator(ctx):
            for e in ctx.entries:
                key = (e.signature_id, e.candidate_id)
                if key not in seen:
                    seen.add(key)
                    if progress_cb is not None:
                        progress_cb(f"{e.signature_id} -> {e.defense_id}", False)
            return {e.signature_id: rs[(ctx.sample_hash, e.candidate_id)] for e in ctx.entries}

        return estimator

    monkeypatch.setattr(llm, "preflight", lambda: None)
    monkeypatch.setattr(llm, "get_estimator", fake_get_estimator)
    return {"n_distinct": len(distinct)}


def test_async_flow_completes_and_matches_sync(stub_llm):
    client = TestClient(main.app)

    with open(SINGLE, "rb") as fh:
        r = client.post("/api/analyze/async", files={"file": ("s.csv", fh, "text/csv")})
    assert r.status_code == 202
    body = r.json()
    job_id = body["job_id"]
    assert body["total"] == stub_llm["n_distinct"]

    snap = None
    for _ in range(100):
        snap = client.get(f"/api/jobs/{job_id}").json()
        if snap["status"] != "running":
            break
    assert snap["status"] == "done"
    assert 0 < snap["done"] <= snap["total"]
    assert snap["warnings"] == 0

    got = snap["result"]["samples"][0]["best_fitness_full"]
    assert got == pytest.approx(NOTEBOOK_BEST_FITNESS, abs=1e-12)

    dl = client.get(f"/api/jobs/{job_id}/download")
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith("text/csv")
    assert "Best_Fitness" in dl.text


def test_async_rejects_bad_file_before_making_a_job(stub_llm):
    client = TestClient(main.app)
    bad = b"Candidate_ID,Hash,Signature_ID,Defense_ID,Attack_Plan_Score,Reduced_Severity\nC1,h,1,17,999,1\n"
    r = client.post("/api/analyze/async", files={"file": ("bad.csv", bad, "text/csv")})
    assert r.status_code == 422
    assert "error" in r.json()


def test_missing_job_returns_404():
    client = TestClient(main.app)
    r = client.get("/api/jobs/deadbeefdead")
    assert r.status_code == 404


def test_download_before_done_is_409(stub_llm, monkeypatch):
    import jobs

    job = jobs.create(total=5)
    client = TestClient(main.app)
    r = client.get(f"/api/jobs/{job.id}/download")
    assert r.status_code == 409
