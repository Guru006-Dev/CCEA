# CCEA backend

FastAPI wrapper around the Cooperative Coevolutionary Algorithm. `ccea_core.py`
is the single implementation; the parity test pins its output to the reference
value (`15232 -> 0.8225830169154041`).

## Run

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Windows   (source .venv/bin/activate on mac/linux)
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | params + LLM status |
| POST | `/api/analyze` | multipart `file=` a `.csv` (CCE.csv schema) or the multi-sheet `.xlsx`; returns JSON |
| POST | `/api/analyze?download=csv` | same, but returns the optimal combinations as a CSV file |
| POST | `/api/analyze?use_llm=true` / `false` | force / skip the LLM estimator for this request |
| POST | `/api/evolve` | multipart `file=`; starts the attack evolution as a job, returns `202 {job_id, total}` (poll with `GET /api/jobs/{id}`) |
| GET | `/api/evolve/{id}/download` | best defense before/after per sample, with the repository count, as CSV |

**Attack evolution result** (`result.samples[]` of the job): `F_original`, `F_evolved`, `generations_run`, `best_generation`,
`stopped_by`, `seed` (`int(Hash) % 1000`), `slots` (total / related / random / fixed), `history[]` (generation, F, best_F,
attack_strength = 1 − best_F, generation_attack, improved, changed, repo_found), `swaps[]` (old, new, link related / random),
`defense_curve_original[]` / `defense_curve_evolved[]` (the defender's best F per generation),
`defense_before_after[]` (signature, defense before/after, status same / changed / new signature) and
`found_in_repo` (real MLRan samples whose whole signature list is inside the evolved sample and that need a swapped-in signature).
The attack evolves as a CCEA (one slot per signature; choices = itself + related signatures, or + 4 random ones).
The defense (`ccea_core.py`) is not changed; it is re-run from scratch on every attack version.

Response: `{ parameters, reduced_severity_source, samples[], aggregate }`.
Each sample has `best_fitness`, `best_generation`, `is_aggr`, `rs_aggr`,
`optimal_combination[]`, `generation_history[]`.

## Files

| File | Purpose |
|---|---|
| `ccea_core.py` | the algorithm — single source of truth, do not fork |
| `main.py` | FastAPI routes + CSV/XLSX parsing |
| `llm.py` | **the only file to edit for LLM integration** |
| `LLM_INTEGRATION.md` | step-by-step for wiring the LLM |
| `tests/test_parity.py` | asserts `15232 → 0.8225830169154041` and that the LLM seam is a no-op when off |
| `attack_evolution.py` | attack evolution as a CCEA (the notebook `attack_evolution/CCEA_Defense_and_Attack_Evolution.ipynb` imports it) |
| `attack_routes.py` | the `/api/evolve` routes (kept apart so the defense routes stay unchanged) |
| `attack_data/` | signature tags (MBC / ATT&CK) and 2,330 real ransomware signature lists (MLRan, CC-BY 4.0); sources in its README |
| `tests/test_attack_evolution.py`, `tests/test_attack_route.py` | reproduce the notebook for sample 15232 (0.7943 → 0.7587, 32 generations, 19 changed), CCEA rules, route flow |
| `sample_data/` | `CCE_single_sample.csv`, `CCE_all_samples.csv`, `CCE_all_samples.xlsx` |

## Test

```bash
pytest -q
```
