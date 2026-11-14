# CCEA Optimizer

Upload a malware report (CSV or XLSX) and get the **best defense for every triggered signature**, found by a
cooperative coevolutionary algorithm (CCEA). An optional second step, **Also evolve the attack**, lets the attack
change its signatures (also as a CCEA) to find the version that is hardest to defend, then looks the evolved sample up
in a public repository of real ransomware.

```
CCEA-Optimizer/
  backend/                FastAPI service
    ccea_core.py          the defense CCEA (single source of truth, parity-tested: do not fork)
    main.py               routes for the defense: /api/analyze, /api/analyze/async, /api/jobs/{id}
    llm.py                the LLM seam for Reduced_Severity (the only file to edit for LLM integration)
    jobs.py               in-memory job registry used by the async routes
    attack_evolution.py   the attack CCEA (same algorithm, turned around)
    attack_routes.py      /api/evolve routes (kept apart so the defense routes stay unchanged)
    mappings/             signature id -> name, defense id -> name
    sample_data/          CCE_single_sample.csv, CCE_all_samples.csv/.xlsx (17 samples, 2,823 rows) = the dataset
    attack_data/          MITRE/MBC tags per signature + 2,330 real ransomware signature lists (MLRan), sources in its README
    tests/                parity test, jobs, async route, attack evolution
  frontend/               static page: upload -> results (index.html, main.js, evolution.js, styles.css)
  docs/                   the knowledge graph of related signatures: picture (png) and Protege file (owl)
  run.bat / run.ps1       start backend (port 8000) and frontend (port 5500) on Windows
```

## Run

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Windows (source .venv/bin/activate on mac/linux)
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
python -m http.server 5500
```

Open http://localhost:5500, upload `backend/sample_data/CCE_all_samples.csv`. On Windows, `run.bat` does all of this
after the first `pip install`.

## Tests

```bash
cd backend
pytest -q
```

Expect 26 passed. The defense must give `15232 -> 0.8225830169154041`; the attack evolution must give
`0.7943 -> 0.7587` for sample 15232.

## LLM integration (for the friends working on it)

`Reduced_Severity` currently comes from the CSV. The LLM is meant to produce it instead. The page has a
**Use LLM for reduced severity** tickbox, and `backend/llm.py` is the seam: everything is described in
`backend/LLM_INTEGRATION.md`. Notes:

- Off by default. Switch it on per request (`/api/analyze?use_llm=true`, `/api/analyze/async`) or with the env var `LLM_ENABLED=1`.
- `llm.py` loads an external evaluator (`evaluate.py`, a Gemini harness that needs `GEMINI_API_KEY`). That harness is **not** in this folder. Point to it with `CUCKOO_EVAL_DIR=<folder with evaluate.py>`. Keep the API key in a `.env` file or the environment; `.gitignore` already blocks `.env` and the harness folder.
- Optional packages for the harness: `google-genai`, `python-dotenv` (commented out in `backend/requirements.txt`).
- The defense (`ccea_core.py`) must stay the single implementation: add the LLM through `llm.py`, not by copying the algorithm.
- "Also evolve the attack" is disabled while "Use LLM" is ticked (the evolution does not use the LLM yet).

## Data sources and credit

- Reference ransomware samples: MLRan dataset, Onwuegbuche et al. 2026, https://zenodo.org/records/23403681, CC-BY 4.0 (only signature lists are kept).
- Signature tags: Malware Behavior Catalog, https://github.com/MBCProject/community (branch `mbc-cuckoo`); MITRE ATT&CK data, https://github.com/mitre-attack/attack-stix-data.
