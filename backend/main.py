"""
FastAPI wrapper around ccea_core.

Run locally:
    cd backend
    python -m venv .venv && .venv\\Scripts\\activate      (Windows)
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import csv
import io

from fastapi import BackgroundTasks, FastAPI, File, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

import ccea_core
import jobs
import llm

app = FastAPI(title="CCEA Optimizer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # local dev; tighten before deploy
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------------
# file parsing
# ----------------------------------------------------------------------
def _rows_from_csv(data: bytes) -> list[dict]:
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return [dict(r) for r in reader]


def _rows_from_xlsx(data: bytes) -> list[dict]:
    """Flatten the multi-sheet CCE_AllSamples.xlsx (one sheet per sample,
    plus optional _README / _AttackScore_Derivation sheets which are skipped)."""
    import openpyxl

    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True, read_only=True)
    rows: list[dict] = []
    for sheet in wb.sheetnames:
        if sheet.startswith("_"):
            continue
        ws = wb[sheet]
        it = ws.iter_rows(values_only=True)
        try:
            header = [str(h).strip() if h is not None else "" for h in next(it)]
        except StopIteration:
            continue
        if "Candidate_ID" not in header or "Signature_ID" not in header:
            continue
        for raw in it:
            if raw is None or all(v is None for v in raw):
                continue
            rec = {header[i]: raw[i] for i in range(min(len(header), len(raw)))}
            if rec.get("Candidate_ID") in (None, ""):
                continue
            rows.append(rec)
    return rows


def _parse_upload(filename: str, data: bytes) -> list[dict]:
    name = (filename or "").lower()
    if name.endswith((".xlsx", ".xlsm")):
        return _rows_from_xlsx(data)
    return _rows_from_csv(data)


# ----------------------------------------------------------------------
# routes
# ----------------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "parameters": ccea_core.PARAMETERS,
        "reduced_severity": llm.status(),
    }


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    download: str | None = Query(None, description="pass 'csv' to get the optimal combinations as a CSV"),
    use_llm: bool | None = Query(
        None,
        description="true = force the LLM estimator, false = force the CSV placeholder, "
                    "omit = follow the LLM_ENABLED env var",
    ),
):
    data = await file.read()
    try:
        rows = _parse_upload(file.filename, data)
        estimator = llm.get_estimator(force=use_llm)
        result = ccea_core.run_all(rows, reduced_severity_fn=estimator)
    except ccea_core.ValidationError as exc:
        return JSONResponse(status_code=422, content={"error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - surface any parse/compute failure to the client
        return JSONResponse(status_code=400, content={"error": f"{type(exc).__name__}: {exc}"})

    if download == "csv":
        return _combinations_csv(result)
    return result


# ----------------------------------------------------------------------
# async LLM path  (the CSV path above stays synchronous)
# ----------------------------------------------------------------------
def _distinct_pairs(rows: list[dict]) -> int:
    return len({
        (str(r.get("Signature_ID")).strip(), str(r.get("Candidate_ID")).strip())
        for r in rows
    })


def _run_llm_job(job_id: str, rows: list[dict]) -> None:
    """Background worker: run the CCEA with the LLM estimator, feeding progress
    into the job. Runs in Starlette's threadpool (it is blocking + network-bound)."""
    job = jobs.get(job_id)
    if job is None:
        return
    try:
        estimator = llm.get_estimator(force=True, progress_cb=job.tick)
        job.finish(ccea_core.run_all(rows, reduced_severity_fn=estimator))
    except ccea_core.ValidationError as exc:
        job.fail(str(exc))
    except llm.LLMUnavailable as exc:
        job.fail(f"LLM not available: {exc}")
    except Exception as exc:  # noqa: BLE001 - any failure becomes a failed job
        job.fail(f"{type(exc).__name__}: {exc}")


@app.post("/api/analyze/async")
async def analyze_async(background: BackgroundTasks, file: UploadFile = File(...)):
    """Start an LLM-backed analysis and return a job id to poll."""
    data = await file.read()
    try:
        rows = ccea_core.validate_and_normalise(_parse_upload(file.filename, data))
    except ccea_core.ValidationError as exc:
        return JSONResponse(status_code=422, content={"error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=400, content={"error": f"{type(exc).__name__}: {exc}"})

    try:
        llm.preflight()
    except llm.LLMUnavailable as exc:
        return JSONResponse(status_code=400, content={"error": f"LLM not available: {exc}"})

    job = jobs.create(total=_distinct_pairs(rows))
    background.add_task(_run_llm_job, job.id, rows)
    return JSONResponse(status_code=202, content={"job_id": job.id, "total": job.total})


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "job not found (it may have expired or the server restarted)"})
    return job.snapshot()


@app.get("/api/jobs/{job_id}/download")
def job_download(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "job not found"})
    if job.status != "done":
        return JSONResponse(status_code=409, content={"error": f"job is {job.status}, nothing to download"})
    return _combinations_csv(job.result)


def _combinations_csv(result: dict) -> StreamingResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "Sample", "Hash", "Best_Fitness", "Best_Generation",
        "Candidate_ID", "Signature_ID", "Defense_ID",
        "Attack_Plan_Score", "Attack_Mapped", "Reduced_Severity", "Reduced_Severity_Mapped",
    ])
    for s in result["samples"]:
        for c in s["optimal_combination"]:
            w.writerow([
                s["label"], s["hash"], s["best_fitness"], s["best_generation"],
                c["candidate_id"], c["signature_id"], c["defense_id"],
                c["attack_plan_score"], c["attack_mapped"], c["reduced_severity"], c["reduced_severity_mapped"],
            ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=optimal_defense_combinations.csv"},
    )


# attack evolution routes (separate file; the defense routes above are unchanged)
from attack_routes import router as _attack_router  # noqa: E402
app.include_router(_attack_router)
