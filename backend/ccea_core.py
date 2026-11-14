"""
Cooperative Coevolutionary Algorithm - shared core.

This module is the SINGLE SOURCE OF TRUTH for the CCEA. Both the notebook
(`CCE_AllSamples.ipynb`) and the backend API import it, so their numbers are
guaranteed identical. Do not fork this logic.

It operates on plain Python rows (list of dicts with the CCE.csv column names)
so it has no pandas dependency; only numpy, for the exact RMS/mean maths used
in the notebook.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Iterable

import numpy as np

# ----------------------------------------------------------------------
# PARAMETERS  (identical to the notebook - Step 2)
# ----------------------------------------------------------------------
RANDOM_SEED = 42
MAX_GENERATIONS = 100
MUTATION_PROBABILITY = 0.20
EXPLORATION_PROBABILITY = 0.25
PATIENCE = 20
MIN_IMPROVEMENT = 1e-8

MIN_MAPPED_SCORE = 0.03        # epsilon               (Parameters!B2)
MAX_ATTACK_PLAN_SCORE = 35     # signature severity max (Parameters!B3)
MAX_REDUCED_SEVERITY = 10

REQUIRED_COLUMNS = [
    "Candidate_ID", "Hash", "Signature_ID",
    "Defense_ID", "Attack_Plan_Score", "Reduced_Severity",
]

SAMPLE_LABELS = {
    "15232": "Sample01", "18327": "Sample02", "71452": "Sample03", "83925": "Sample04",
    "19564": "Sample05", "26137": "Sample06", "29178": "Sample07", "31247": "Sample08",
    "90009": "Sample09", "48791": "Sample10", "58934": "Sample11", "98265": "Sample12",
    "98250": "Sample13", "98248": "Sample14", "98360": "Sample15", "98241": "Sample16",
    "98242": "Sample17",
}

PARAMETERS = {
    "random_seed": RANDOM_SEED,
    "max_generations": MAX_GENERATIONS,
    "mutation_probability": MUTATION_PROBABILITY,
    "exploration_probability": EXPLORATION_PROBABILITY,
    "patience": PATIENCE,
    "min_improvement": MIN_IMPROVEMENT,
    "min_mapped_score": MIN_MAPPED_SCORE,
    "max_attack_plan_score": MAX_ATTACK_PLAN_SCORE,
    "max_reduced_severity": MAX_REDUCED_SEVERITY,
}


class ValidationError(ValueError):
    """Raised when an uploaded dataset fails the notebook's Step-4 checks."""


# ======================================================================
# LLM INTEGRATION SEAM  --  the only thing your friend needs to touch
# ======================================================================
#
# Reduced severity ("how much attack severity is LEFT after the defense")
# is the value an LLM is meant to produce. Everywhere else in the CCEA is
# fixed maths. To plug an LLM in you supply ONE function:
#
#     def my_estimator(ctx: CombinationContext) -> dict[str, float]:
#         # ctx gives you, per signature:
#         #   - signature_id, chosen candidate_id, chosen defense_id
#         #   - raw + [0,1]-mapped attack score
#         # return {signature_id: reduced_severity_raw}  (0 .. MAX_REDUCED_SEVERITY)
#         ...
#
# and pass it in:   run_all(rows, reduced_severity_fn=my_estimator)
#
# The function is called ONCE per complete defense combination (i.e. once
# per generation per sample), receiving the whole attack plan + whole
# defense combination together - exactly the workflow spec.
#
# When reduced_severity_fn is None (the default), the CSV's Reduced_Severity
# column is used unchanged, so output stays identical to the notebook.
#
# A ready-made stub + caching wrapper + Anthropic example live in `llm.py`.
# ======================================================================


@dataclass(frozen=True)
class SignatureContext:
    """One signature's slice of a complete combination, handed to the LLM."""
    signature_id: str
    candidate_id: str
    defense_id: str              # chosen defensive control (catalog id)
    attack_plan_score: float     # raw, 1 .. MAX_ATTACK_PLAN_SCORE
    attack_mapped: float         # [0, 1]


@dataclass(frozen=True)
class CombinationContext:
    """The full attack plan + full defense combination for one evaluation.

    Passed to `reduced_severity_fn`, which must return
    {signature_id: reduced_severity_raw} covering every entry."""
    sample_hash: str
    generation: int
    entries: tuple  # tuple[SignatureContext, ...]  (frozen -> hashable -> cacheable)

    def to_payload(self) -> dict:
        """Plain-dict view, handy for building an LLM prompt / request body."""
        return {
            "sample_hash": self.sample_hash,
            "generation": self.generation,
            "max_reduced_severity": MAX_REDUCED_SEVERITY,
            "signatures": [
                {
                    "signature_id": e.signature_id,
                    "candidate_id": e.candidate_id,
                    "defense_id": e.defense_id,
                    "attack_plan_score": e.attack_plan_score,
                    "attack_score_mapped": e.attack_mapped,
                }
                for e in self.entries
            ],
        }


# Type alias for the pluggable estimator.
ReducedSeverityFn = Callable[[CombinationContext], dict]


# ----------------------------------------------------------------------
# Candidate  (notebook - Step 5)
# ----------------------------------------------------------------------
@dataclass
class DefenseCandidate:
    candidate_id: str
    signature_id: str
    defense_id: str
    attack_plan_score: float
    reduced_severity: float          # from the CSV - placeholder for the LLM output

    fitness_history: list = field(default_factory=list)
    evaluation_count: int = 0

    @property
    def mean_fitness(self) -> float:
        return float(np.mean(self.fitness_history)) if self.fitness_history else float("-inf")

    @property
    def best_fitness(self) -> float:
        return float(np.max(self.fitness_history)) if self.fitness_history else float("-inf")


# ----------------------------------------------------------------------
# Validation  (notebook - Step 4)
# ----------------------------------------------------------------------
def validate_and_normalise(rows: list[dict]) -> list[dict]:
    """Clean identifier/numeric columns and run every range check. Returns
    normalised rows or raises ValidationError with a human-readable message."""
    if not rows:
        raise ValidationError("The file contains no data rows.")

    cols = {c.replace(" ", " ").strip() for c in rows[0].keys()}
    missing = [c for c in REQUIRED_COLUMNS if c not in cols]
    if missing:
        raise ValidationError(f"Missing required columns: {missing}")

    out = []
    seen = set()
    for i, raw in enumerate(rows, start=2):  # row 1 is the header
        row = {k.replace(" ", " ").strip(): v for k, v in raw.items()}
        rec = {}
        for c in ("Candidate_ID", "Hash", "Signature_ID", "Defense_ID"):
            rec[c] = str(row[c]).strip()
            if rec[c].endswith(".0"):
                rec[c] = rec[c][:-2]
        for c in ("Attack_Plan_Score", "Reduced_Severity"):
            try:
                rec[c] = float(str(row[c]).strip())
            except (TypeError, ValueError):
                raise ValidationError(
                    f"Row {i}: column '{c}' has a non-numeric value {row[c]!r}."
                )
            if math.isnan(rec[c]):
                raise ValidationError(f"Row {i}: column '{c}' is empty/NaN.")

        key = (rec["Hash"], rec["Candidate_ID"])
        if key in seen:
            raise ValidationError(
                f"Row {i}: duplicate (Hash, Candidate_ID) = {key}."
            )
        seen.add(key)

        if not rec["Defense_ID"]:
            raise ValidationError(f"Row {i}: Defense_ID is empty.")
        if not (1 <= rec["Attack_Plan_Score"] <= MAX_ATTACK_PLAN_SCORE):
            raise ValidationError(
                f"Row {i}: Attack_Plan_Score {rec['Attack_Plan_Score']} outside 1..{MAX_ATTACK_PLAN_SCORE}."
            )
        if not (0 <= rec["Reduced_Severity"] <= MAX_REDUCED_SEVERITY):
            raise ValidationError(
                f"Row {i}: Reduced_Severity {rec['Reduced_Severity']} outside 0..{MAX_REDUCED_SEVERITY}."
            )
        out.append(rec)
    return out


# ----------------------------------------------------------------------
# CCEA operators  (notebook - Step 6/7)
# ----------------------------------------------------------------------
def calculate_rms(values: Iterable[float]) -> float:
    arr = np.asarray(list(values), dtype=float)
    if arr.size == 0:
        raise ValueError("Cannot calculate RMS from an empty list.")
    return float(np.sqrt(np.mean(np.square(arr))))


def create_subpopulations(sample_rows: list[dict], signature_order: list[str]) -> dict:
    subpops: dict[str, list[DefenseCandidate]] = {}
    for sig in signature_order:
        subpops[sig] = [
            DefenseCandidate(
                candidate_id=r["Candidate_ID"],
                signature_id=r["Signature_ID"],
                defense_id=str(r["Defense_ID"]),
                attack_plan_score=float(r["Attack_Plan_Score"]),
                reduced_severity=float(r["Reduced_Severity"]),
            )
            for r in sample_rows if r["Signature_ID"] == sig
        ]
    return subpops


def select_representative(candidates: list[DefenseCandidate]):
    unexplored = [c for c in candidates if c.evaluation_count == 0]
    if unexplored:
        return random.choice(unexplored), "Unexplored"
    if random.random() < EXPLORATION_PROBABILITY:
        return random.choice(candidates), "Random Exploration"
    best = max(candidates, key=lambda c: (c.mean_fitness, c.best_fitness))
    return best, "Collaborative Fitness"


def mutate_candidate(selected: DefenseCandidate, candidates: list[DefenseCandidate]):
    if len(candidates) <= 1:
        return selected, False
    if random.random() >= MUTATION_PROBABILITY:
        return selected, False
    alternatives = [c for c in candidates if c.candidate_id != selected.candidate_id]
    return random.choice(alternatives), True


def construct_combination(subpopulations: dict):
    combination = {}
    selection_log = []
    for sig, candidates in subpopulations.items():
        selected, method = select_representative(candidates)
        final, mutated = mutate_candidate(selected, candidates)
        combination[sig] = final
        selection_log.append({
            "Signature_ID": sig,
            "Initially_Selected": selected.candidate_id,
            "Final_Candidate": final.candidate_id,
            "Selection_Method": method,
            "Mutation": mutated,
        })
    return combination, selection_log


def _map_attack(raw: float) -> float:
    return MIN_MAPPED_SCORE + (1 - MIN_MAPPED_SCORE) * (raw - 1) / (MAX_ATTACK_PLAN_SCORE - 1)


def evaluate_combination(
    sample_hash: str,
    generation: int,
    combination: dict,
    reduced_severity_fn: "ReducedSeverityFn | None" = None,
) -> dict:
    """Score one complete defense combination.

    `reduced_severity_fn` is the LLM seam. If None, each candidate's CSV
    Reduced_Severity is used (identical to the notebook). If given, it is
    called ONCE with the whole combination and must return
    {signature_id: reduced_severity_raw} for every signature."""

    # 1. map every signature's attack severity to [0, 1]
    entries = []
    for sig, cand in combination.items():
        am = _map_attack(cand.attack_plan_score)
        if not (0 <= am <= 1):
            raise ValueError(f"Invalid mapped Attack for {cand.candidate_id}")
        entries.append(SignatureContext(
            signature_id=sig, candidate_id=cand.candidate_id, defense_id=cand.defense_id,
            attack_plan_score=cand.attack_plan_score, attack_mapped=am,
        ))

    # 2. reduced severity: LLM (whole combination at once) or CSV placeholder
    if reduced_severity_fn is None:
        rs_raw_by_sig = {sig: cand.reduced_severity for sig, cand in combination.items()}
    else:
        ctx = CombinationContext(sample_hash=sample_hash, generation=generation,
                                 entries=tuple(entries))
        rs_raw_by_sig = dict(reduced_severity_fn(ctx))
        missing = [e.signature_id for e in entries if e.signature_id not in rs_raw_by_sig]
        if missing:
            raise ValueError(f"reduced_severity_fn did not return values for signatures: {missing}")

    # 3. finalise per-signature detail + aggregation inputs
    mapped_attack, mapped_rs, details = [], [], []
    for e, (sig, cand) in zip(entries, combination.items()):
        reduced_severity_raw = float(rs_raw_by_sig[sig])
        if not (0 <= reduced_severity_raw <= MAX_REDUCED_SEVERITY):
            raise ValueError(
                f"reduced_severity for {sig} is {reduced_severity_raw}, "
                f"outside 0..{MAX_REDUCED_SEVERITY}"
            )
        reduced_severity_mapped = reduced_severity_raw / MAX_REDUCED_SEVERITY

        mapped_attack.append(e.attack_mapped)
        mapped_rs.append(reduced_severity_mapped)
        details.append({
            "Hash": sample_hash, "Generation": generation,
            "Candidate_ID": cand.candidate_id, "Signature_ID": sig,
            "Defense_ID": cand.defense_id,
            "Attack_Plan_Score": cand.attack_plan_score, "Attack_Mapped": e.attack_mapped,
            "Reduced_Severity": reduced_severity_raw,
            "Reduced_Severity_Mapped": reduced_severity_mapped,
        })

    IS_Aggr = calculate_rms(mapped_attack)
    RS_Aggr = calculate_rms(mapped_rs)
    fitness = 0.0 if math.isclose(IS_Aggr, 0.0, abs_tol=1e-12) else (IS_Aggr - RS_Aggr) / IS_Aggr

    for cand in combination.values():
        cand.fitness_history.append(fitness)
        cand.evaluation_count += 1

    return {
        "Hash": sample_hash, "Generation": generation, "Combination": combination,
        "Combination_Details": details,
        "IS_Aggr": float(IS_Aggr), "RS_Aggr": float(RS_Aggr), "Fitness": float(fitness),
    }


def all_candidates_evaluated(subpopulations: dict) -> bool:
    return all(c.evaluation_count > 0
               for cs in subpopulations.values() for c in cs)


# ----------------------------------------------------------------------
# Per-sample run  (notebook - Step 8)
# ----------------------------------------------------------------------
def run_ccea_for_sample(
    sample_hash: str,
    sample_rows: list[dict],
    seed: int = RANDOM_SEED,
    reduced_severity_fn: "ReducedSeverityFn | None" = None,
) -> dict:
    signature_order = list(dict.fromkeys(r["Signature_ID"] for r in sample_rows))
    subpops = create_subpopulations(sample_rows, signature_order)

    for cs in subpops.values():
        for c in cs:
            c.fitness_history = []
            c.evaluation_count = 0
    random.seed(seed)
    np.random.seed(seed)

    search_space = 1
    for cs in subpops.values():
        search_space *= len(cs)

    best_result = None
    no_improve = 0
    generation_history = []
    generation = 0

    for generation in range(1, MAX_GENERATIONS + 1):
        combination, _ = construct_combination(subpops)
        result = evaluate_combination(sample_hash, generation, combination, reduced_severity_fn)

        improved = (best_result is None
                    or result["Fitness"] > best_result["Fitness"] + MIN_IMPROVEMENT)
        if improved:
            best_result = result
            no_improve = 0
        else:
            no_improve += 1

        generation_history.append({
            "generation": generation,
            "generation_fitness": result["Fitness"],
            "best_fitness_so_far": best_result["Fitness"],
            "is_aggr": result["IS_Aggr"],
            "rs_aggr": result["RS_Aggr"],
        })

        if all_candidates_evaluated(subpops) and no_improve >= PATIENCE:
            break

    return {
        "hash": sample_hash,
        "label": SAMPLE_LABELS.get(sample_hash, ""),
        "n_signatures": len(signature_order),
        "n_candidates": int(sum(len(cs) for cs in subpops.values())),
        "search_space": str(search_space),
        "generations_run": generation,
        "best_generation": best_result["Generation"],
        "is_aggr": round(best_result["IS_Aggr"], 6),
        "rs_aggr": round(best_result["RS_Aggr"], 6),
        "best_fitness": round(best_result["Fitness"], 6),
        "best_fitness_full": best_result["Fitness"],
        "optimal_combination": [
            {
                "candidate_id": d["Candidate_ID"],
                "signature_id": d["Signature_ID"],
                "defense_id": d["Defense_ID"],
                "attack_plan_score": d["Attack_Plan_Score"],
                "attack_mapped": round(d["Attack_Mapped"], 6),
                "reduced_severity": d["Reduced_Severity"],
                "reduced_severity_mapped": round(d["Reduced_Severity_Mapped"], 6),
            }
            for d in best_result["Combination_Details"]
        ],
        "generation_history": generation_history,
    }


# ----------------------------------------------------------------------
# Whole-dataset run  (notebook - Step 9/10)
# ----------------------------------------------------------------------
def run_all(rows: list[dict], reduced_severity_fn: "ReducedSeverityFn | None" = None) -> dict:
    """Run the CCEA over every sample in `rows`.

    reduced_severity_fn: optional LLM estimator (see the LLM INTEGRATION SEAM
    block above). None -> use the CSV Reduced_Severity, output matches the notebook."""
    rows = validate_and_normalise(rows)

    order = list(dict.fromkeys(r["Hash"] for r in rows))
    samples = []
    for i, h in enumerate(order):
        sample_rows = [r for r in rows if r["Hash"] == h]
        samples.append(run_ccea_for_sample(
            h, sample_rows, seed=RANDOM_SEED + i, reduced_severity_fn=reduced_severity_fn,
        ))

    fits = [s["best_fitness_full"] for s in samples]
    arr = np.asarray(fits, dtype=float)
    aggregate = {
        "n_samples": len(samples),
        "best_fitness": {
            "mean": round(float(arr.mean()), 6),
            "std": round(float(arr.std(ddof=1)) if len(arr) > 1 else 0.0, 6),
            "min": round(float(arr.min()), 6),
            "median": round(float(np.median(arr)), 6),
            "max": round(float(arr.max()), 6),
        },
    }
    return {
        "parameters": PARAMETERS,
        "reduced_severity_source": "llm" if reduced_severity_fn is not None else "csv_placeholder",
        "samples": samples,
        "aggregate": aggregate,
    }
