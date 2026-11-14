"""Routes for the attack evolution (kept apart from main.py so the defense routes stay untouched).

POST /api/evolve                 start a job (polled with the existing GET /api/jobs/{id})
GET  /api/evolve/{id}/download   before/after best defense per sample, as CSV
"""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, BackgroundTasks, File, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

import attack_evolution as ae
import ccea_core
import jobs

router = APIRouter()


def _run(job_id: str, rows: list[dict]) -> None:
    job = jobs.get(job_id)
    if job is None:
        return
    try:
        ev = ae.Evolver(rows)
        hashes = list(dict.fromkeys(r['Hash'] for r in rows))
        out = []
        for h in hashes:
            label = next((r.get('label') for r in rows if r['Hash'] == h and r.get('label')), h)
            res = ae.evolve_sample(ev, h, progress=lambda t, h=h: setattr(job, 'current_pair', f'sample {h}: round {t}'))
            res['label'] = label
            out.append(res)
            job.tick(f'sample {h} done')
        job.finish({'samples': out})
    except ccea_core.ValidationError as exc:
        job.fail(str(exc))
    except Exception as exc:  # noqa: BLE001
        job.fail(f'{type(exc).__name__}: {exc}')


@router.post('/api/evolve')
async def evolve(background: BackgroundTasks, file: UploadFile = File(...)):
    from main import _parse_upload   # reuse the defense side's parser, unchanged
    data = await file.read()
    try:
        rows = ccea_core.validate_and_normalise(_parse_upload(file.filename, data))
    except ccea_core.ValidationError as exc:
        return JSONResponse(status_code=422, content={'error': str(exc)})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=400, content={'error': f'{type(exc).__name__}: {exc}'})
    job = jobs.create(total=len({r['Hash'] for r in rows}))
    background.add_task(_run, job.id, rows)
    return JSONResponse(status_code=202, content={'job_id': job.id, 'total': job.total})


@router.get('/api/evolve/{job_id}/download')
def evolve_download(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={'error': 'job not found'})
    if job.status != 'done' or not isinstance(job.result, dict) or 'samples' not in job.result:
        return JSONResponse(status_code=409, content={'error': f'job is {job.status}, nothing to download'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['Hash', 'Defense_score_original', 'Defense_score_evolved', 'Generations', 'Signatures_changed',
                'Real_samples_found_in_repo', 'Signature', 'Defense_original_attack', 'Defense_evolved_attack', 'Status'])
    for s in job.result['samples']:
        for r in s['defense_before_after']:
            w.writerow([s['hash'], s['F_original'], s['F_evolved'], s['generations_run'], len(s['swaps']),
                        s['found_in_repo']['n_samples'], r['signature'], r['defense_before'] or '', r['defense_after'], r['status']])
    return StreamingResponse(iter([buf.getvalue()]), media_type='text/csv',
                             headers={'Content-Disposition': 'attachment; filename=attack_evolution_results.csv'})
