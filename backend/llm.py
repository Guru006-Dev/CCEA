"""
LLM option for `Reduced_Severity`.

The CCEA needs one number it does not compute itself: **reduced severity** - how
much attack severity is LEFT after a defense is applied.

There are two sources, chosen with a toggle:

  * OFF (default)  -> use the `Reduced_Severity` value already in the CSV
  * ON             -> ask an LLM, via the Gemini evaluator in
                      `AG Cuckoo Very new/evaluate.py` (per signature-defense pair)

Toggle it with:
  - env  LLM_ENABLED=1
  - or per request:  POST /api/analyze?use_llm=true   (?use_llm=false forces OFF)

This module is a thin ADAPTER between the CCEA seam and that evaluator. The
evaluator itself (prompt, model, Initial_Severity handling, deps) lives in
`evaluate.py` and is configured there / via its own `.env`.
"""

from __future__ import annotations

import csv
import os
import sys
import threading
from pathlib import Path

import ccea_core
from ccea_core import CombinationContext

# ----------------------------------------------------------------------
# config
# ----------------------------------------------------------------------
LLM_ENABLED = os.getenv("LLM_ENABLED", "0").lower() in ("1", "true", "yes", "on")

# Folder that holds evaluate.py + windows/ + data.csv  (the Gemini harness).
# Override with the CUCKOO_EVAL_DIR env var.
_DEFAULT_EVAL_DIRS = [
    Path(os.getenv("CUCKOO_EVAL_DIR", "")) if os.getenv("CUCKOO_EVAL_DIR") else None,
    Path(__file__).resolve().parents[2] / "AG Cuckoo Very new",          # repo_root/AG Cuckoo Very new
    Path.home() / "Desktop" / "Project" / "CCE" / "AG Cuckoo Very new",  # dev machine
]
EVAL_DIR = next((p for p in _DEFAULT_EVAL_DIRS if p and p.is_dir()), None)

_MAP_DIR = Path(__file__).resolve().parent / "mappings"


class LLMUnavailable(RuntimeError):
    """Raised when the LLM option is requested but the harness is not set up."""


# ----------------------------------------------------------------------
# lazy loaders  (nothing runs until the LLM option is actually used)
# ----------------------------------------------------------------------
_evaluate_mod = None
_sig_index = None
_sig_id2name: dict[str, str] = {}
_def_id2name: dict[str, str] = {}
_initial_sev: dict[str, int] = {}


def _load_id_maps() -> None:
    if _sig_id2name and _def_id2name:
        return
    for fn, tgt, kcol, vcol in (
        ("signature_id_name.csv", _sig_id2name, "Signature_ID", "Signature_Name"),
        ("defense_id_name.csv", _def_id2name, "Defense_ID", "Defense_Name"),
    ):
        path = _MAP_DIR / fn
        if not path.exists():
            raise LLMUnavailable(f"missing id->name map: {path}")
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                tgt[str(row[kcol]).strip()] = str(row[vcol]).strip()


def _load_initial_severity() -> None:
    """Initial_Severity (1..6 band) per signature, read from the harness data.csv.
    (Extending this to every sample is the evaluator owner's job - point 4.)"""
    if _initial_sev:
        return
    if EVAL_DIR is None:
        raise LLMUnavailable(
            "CUCKOO_EVAL_DIR not found. Point it at the folder containing "
            "evaluate.py / windows/ / data.csv."
        )
    data_csv = EVAL_DIR / "data.csv"
    if not data_csv.exists():
        raise LLMUnavailable(f"missing {data_csv}")
    with open(data_csv, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]
        col = {h: i for i, h in enumerate(header) if h}
        si, vi = col["Signature_Name"], col["Initial_Severity"]
        for r in reader:
            if len(r) > max(si, vi) and r[si].strip():
                try:
                    _initial_sev[r[si].strip()] = int(r[vi].strip())
                except ValueError:
                    pass


def _load_evaluator():
    global _evaluate_mod, _sig_index
    if _evaluate_mod is not None:
        return _evaluate_mod
    if EVAL_DIR is None:
        raise LLMUnavailable(
            "The Gemini evaluator folder was not found. Set CUCKOO_EVAL_DIR to the "
            "folder containing evaluate.py, windows/ and data.csv."
        )
    sys.path.insert(0, str(EVAL_DIR))
    try:
        import evaluate as _ev  # noqa: PLC0415  (deliberately lazy)
    except Exception as exc:  # noqa: BLE001
        raise LLMUnavailable(
            f"could not import evaluate.py from {EVAL_DIR}: {exc}. "
            "Install its deps (pip install google-genai python-dotenv requests) and "
            "set GEMINI_API_KEY."
        ) from exc
    _evaluate_mod = _ev
    _sig_index = _ev.build_signature_index(EVAL_DIR / "windows")
    return _ev


# ======================================================================
# the estimator passed to ccea_core.run_all(reduced_severity_fn=...)
# ======================================================================
# Two caches:
#   _PAIR_CACHE  - one entry per distinct (signature_id, candidate_id); this is
#                  what bounds the number of real Gemini calls to N-distinct-pairs
#                  and what the async progress bar counts.
#   _CACHE       - one entry per whole combination (pair-set); a cheap short
#                  circuit so a repeated combination does not even re-loop.
_CACHE: dict[tuple, dict] = {}
_PAIR_CACHE: dict[tuple, float] = {}
_PAIR_LOCK = threading.Lock()

# progress_cb(pair_label: str, degraded: bool) - called once per pair the FIRST
# time it is sent to the evaluator (never on a cache hit). `degraded` is True
# when the evaluator could not score the pair and fell back to worst case.
ProgressCb = "callable"


def _cache_key(ctx: CombinationContext) -> tuple:
    return tuple(sorted((e.signature_id, e.candidate_id) for e in ctx.entries))


def _call_llm(ctx: CombinationContext, progress_cb=None) -> dict:
    """One (signature, defense) LLM evaluation per entry -> {signature_id: reduced_severity}."""
    ev = _load_evaluator()
    _load_id_maps()
    _load_initial_severity()

    out: dict[str, float] = {}
    for e in ctx.entries:
        pkey = (str(e.signature_id), str(e.candidate_id))
        cached = _PAIR_CACHE.get(pkey)
        if cached is not None:
            out[str(e.signature_id)] = cached
            continue

        sig_name = _sig_id2name.get(str(e.signature_id))
        def_name = _def_id2name.get(str(e.defense_id))
        if sig_name is None:
            raise LLMUnavailable(f"no signature name for Signature_ID={e.signature_id}")
        if def_name is None:
            raise LLMUnavailable(f"no defense name for Defense_ID={e.defense_id}")
        is_band = _initial_sev.get(sig_name)
        if is_band is None:
            raise LLMUnavailable(
                f"no Initial_Severity for signature {sig_name!r} in {EVAL_DIR / 'data.csv'} "
                "(point 4 - extend data.csv to cover every sample's signatures)."
            )
        row = ev.CsvRow(sig_name, def_name, is_band)
        res = ev.evaluate_row(row, _sig_index.get(sig_name), run_id="ccea")
        val = float(res.llm_value)
        with _PAIR_LOCK:
            _PAIR_CACHE[pkey] = val
        out[str(e.signature_id)] = val
        if progress_cb is not None:
            degraded = str(getattr(res, "mitigation_label", "")).upper() == "UNKNOWN"
            progress_cb(f"{sig_name} -> {def_name}", degraded)
    return out


def estimate_reduced_severity(ctx: CombinationContext, progress_cb=None) -> dict:
    """Cached LLM estimator. Same (signature, defense) set -> same result."""
    key = _cache_key(ctx)
    if key not in _CACHE:
        result = {str(k): float(v) for k, v in _call_llm(ctx, progress_cb).items()}
        for sid, v in result.items():
            if not (0 <= v <= ccea_core.MAX_REDUCED_SEVERITY):
                raise ValueError(
                    f"LLM returned reduced_severity {v} for {sid}, "
                    f"outside 0..{ccea_core.MAX_REDUCED_SEVERITY}"
                )
        _CACHE[key] = result
    return _CACHE[key]


def clear_cache() -> None:
    _CACHE.clear()
    with _PAIR_LOCK:
        _PAIR_CACHE.clear()


# ======================================================================
# factory  -  used by main.py
# ======================================================================
def get_estimator(force: bool | None = None, progress_cb=None):
    """Return the LLM estimator, or None to use the CSV Reduced_Severity.

    force=True  -> LLM  (ignores LLM_ENABLED)
    force=False -> CSV
    force=None  -> follow the LLM_ENABLED env var

    progress_cb, if given, is called once per distinct (signature, defense) pair
    the first time it is evaluated - used by the async job to drive a progress bar.
    """
    use = LLM_ENABLED if force is None else force
    if not use:
        return None
    if progress_cb is None:
        return estimate_reduced_severity
    return lambda ctx: estimate_reduced_severity(ctx, progress_cb)


def preflight() -> None:
    """Raise LLMUnavailable unless the Gemini harness can actually be loaded.

    Runs (and caches) the lazy loaders, so the async route can reject a request
    up front instead of creating a job that is doomed to fail."""
    _load_evaluator()
    _load_id_maps()
    _load_initial_severity()


def status() -> dict:
    """Small dict for /api/health."""
    return {
        "llm_enabled": LLM_ENABLED,
        "source": "llm (Gemini via evaluate.py)" if LLM_ENABLED else "csv (Reduced_Severity column)",
        "eval_dir": str(EVAL_DIR) if EVAL_DIR else None,
        "eval_dir_found": EVAL_DIR is not None,
    }
