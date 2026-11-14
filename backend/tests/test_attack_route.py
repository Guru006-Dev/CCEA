"""The /api/evolve job route end to end on the single-sample file."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

SINGLE = os.path.join(os.path.dirname(__file__), "..", "sample_data", "CCE_single_sample.csv")


def test_evolve_flow():
    client = TestClient(main.app)
    with open(SINGLE, "rb") as fh:
        r = client.post("/api/evolve", files={"file": ("s.csv", fh, "text/csv")})
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    snap = client.get(f"/api/jobs/{job_id}").json()
    assert snap["status"] == "done", snap
    s = snap["result"]["samples"][0]
    assert s["F_evolved"] <= s["F_original"]
    assert "found_in_repo" in s and s["history"][0]["generation"] == 0
    curve = [g["best_F"] for g in s["defense_curve_original"]]
    assert curve[-1] >= curve[0] and all(b >= a for a, b in zip(curve, curve[1:]))
    dl = client.get(f"/api/evolve/{job_id}/download")
    assert dl.status_code == 200 and "Defense_evolved_attack" in dl.text


def test_evolve_rejects_bad_file():
    client = TestClient(main.app)
    bad = b"Candidate_ID,Hash,Signature_ID,Defense_ID,Attack_Plan_Score,Reduced_Severity\nC1,h,1,17,999,1\n"
    r = client.post("/api/evolve", files={"file": ("bad.csv", bad, "text/csv")})
    assert r.status_code == 422


def test_evolve_download_unknown_job():
    assert TestClient(main.app).get("/api/evolve/nope/download").status_code == 404
