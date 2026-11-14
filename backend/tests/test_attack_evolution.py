"""Attack evolution (attack CCEA) tests: reproduce the notebook and check the algorithm's rules.

Run:  cd backend && pytest -q
"""
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import attack_evolution as ae  # noqa: E402
import ccea_core  # noqa: E402


@pytest.fixture(scope="module")
def ev():
    return ae.Evolver([])


@pytest.fixture(scope="module")
def result(ev):
    return ae.evolve_sample(ev, "15232")


def test_reproduces_notebook(result):
    """Same numbers as section 8 of the notebook for sample 15232 (seed 232)."""
    assert result["seed"] == 232
    assert result["F_original"] == pytest.approx(0.7942553767756007, abs=1e-12)
    assert result["F_evolved"] == pytest.approx(0.7586816316062998, abs=1e-12)
    assert result["generations_run"] == 32
    assert len(result["swaps"]) == 19
    assert result["found_in_repo"]["n_samples"] == 59


def test_first_defense_is_iteration_one(result):
    """Generation 0 is the original sample, unchanged."""
    g0 = result["history"][0]
    assert g0["generation"] == 0 and g0["changed"] == 0 and g0["F"] == result["F_original"]


def test_best_score_never_rises(result):
    best = [h["best_F"] for h in result["history"]]
    assert all(b <= a for a, b in zip(best, best[1:]))
    assert best[-1] == result["F_evolved"]


def test_stopping_rule(result):
    assert result["generations_run"] <= ccea_core.MAX_GENERATIONS
    if result["stopped_by"] == "patience":
        assert result["generations_run"] - result["best_generation"] >= ccea_core.PATIENCE
        assert not any(h["improved"] for h in result["history"][-ccea_core.PATIENCE:])


def test_slots(ev):
    """Every original signature is a slot; related slots offer only neighbours, random slots 4 random choices;
    no slot offers another slot's original signature or the blank id."""
    rng = random.Random(0)
    for h in ("15232", "29178"):
        orig = ev.original(h)
        slots = ev.slots(h, rng)
        assert [s.original for s in slots] == orig
        for s in slots:
            others = [c.sig for c in s.choices[1:]]
            assert s.choices[0].sig == s.original
            assert "nan" not in others and not (set(others) & set(orig))
            if s.kind == "related":
                assert set(others) <= set(ev.neighbors[s.original])
            elif s.kind == "random":
                assert len(others) == ae.N_RANDOM_CHOICES
            else:
                assert others == []


def test_every_attack_has_no_duplicates(ev):
    rng = random.Random(1)
    slots = ev.slots("15232", rng)
    for _ in range(300):
        attack = [c.sig for c in ev.build_attack(slots, rng)]
        assert len(attack) == len(slots) and len(set(attack)) == len(attack)


def test_swaps_are_labelled(result):
    assert all(s["link"] in ("related", "random") for s in result["swaps"])
    assert all(s["new"] != "nan" for s in result["swaps"])


def test_found_in_repo(ev):
    orig = ev.original("15232")
    assert ev.found_in_repo(orig, orig)["n_samples"] == 0      # no new signature -> nothing counts


def test_seed_rule():
    assert ae.sample_seed("15232") == 232
    assert ae.sample_seed("15232", 2) == 2232
    assert 0 <= ae.sample_seed("abc") < 1000


def test_uploaded_file_gives_same_result_as_notebook(result):
    """The upload parser gives '' for a blank Signature_ID (pandas gives 'nan'); both must behave the same."""
    import main
    with open(os.path.join(os.path.dirname(__file__), "..", "sample_data", "CCE_all_samples.csv"), "rb") as fh:
        rows = ccea_core.validate_and_normalise(main._parse_upload("a.csv", fh.read()))
    got = ae.evolve_sample(ae.Evolver(rows), "15232")
    assert got["F_evolved"] == pytest.approx(result["F_evolved"], abs=1e-12)
    assert len(got["swaps"]) == len(result["swaps"])
