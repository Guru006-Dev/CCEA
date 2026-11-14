"""Attack evolution as a cooperative coevolutionary algorithm (CCEA), mirroring the defense side.

Every signature of the uploaded sample is a *slot*. A slot's choices are the signature itself plus its
neighbours in the knowledge graph (signatures that share an MBC / ATT&CK tag). A signature with no neighbour
gets itself plus 4 random signatures from the pool, fixed for the whole run. A signature with no defense data
(or a blank id) keeps itself.

Each generation builds one attack by taking one choice from every slot (unexplored first, then exploration
with p_e, otherwise the choice with the best credit, then mutation with p_m; the same rules as
ccea_core.select_representative / mutate_candidate). The defense (ccea_core.run_ccea_for_sample, unchanged)
answers with its best defense and the score F. Every choice that took part gets the credit 1 - F (a lower F
means a harder attack). The hardest attack so far is kept. Stopping rule = the defense's: every choice tried
and PATIENCE generations without improvement, or MAX_GENERATIONS.

At the end the evolved attack is looked up in a held-out public repository (MLRan, 2,330 real ransomware
samples, CC-BY 4.0). The repository is never used to build the attack; per generation the count is only recorded.
"""
from __future__ import annotations

import csv
import random
import threading
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import ccea_core as core

HERE = Path(__file__).resolve().parent
DATA = HERE / 'attack_data'
LIBRARY_CSV = HERE / 'sample_data' / 'CCE_all_samples.csv'
REPO_URL = 'https://zenodo.org/records/23403681'
N_RANDOM_CHOICES = 4      # extra choices for a signature with no neighbour (the median neighbour count)

# ccea_core seeds Python's global random generator, so defense runs must not overlap.
_LOCK = threading.Lock()


def _read(path):
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def _load_static():
    names = {str(int(r['Signature_ID'])): r['Signature_Name'].lower() for r in _read(HERE / 'mappings' / 'signature_id_name.csv')}
    dnames = {str(r['Defense_ID']): r['Defense_Name'] for r in _read(HERE / 'mappings' / 'defense_id_name.csv')}
    tags = {}
    for r in _read(DATA / 'signature_tags.csv'):
        tags.setdefault(str(r['Signature_ID']), set()).add(r['technique'])
    ref, n_ref = [], 0
    for r in _read(DATA / 'reference_ransomware_signature_sets.csv'):
        n_ref += 1
        l = [s for s in (r['signatures'] or '').split(';') if s]
        if l:
            ref.append((r['family'], frozenset(l)))
    return names, dnames, tags, ref, n_ref


ID2NAME, DEF_NAME, TAGS, REF, REPO_SIZE = _load_static()   # REPO_SIZE = 2,330 samples (a few have no signature)


def _library_rows():
    import pandas as pd
    return core.validate_and_normalise(pd.read_csv(LIBRARY_CSV).to_dict('records'))


@dataclass
class Choice:
    """One signature a slot can take, with the credit it has earned (attack score 1 - F of every attack it was in)."""
    sig: str
    credits: list = field(default_factory=list)

    @property
    def tried(self):
        return len(self.credits)

    @property
    def mean(self):
        return sum(self.credits) / len(self.credits) if self.credits else float('-inf')

    @property
    def best(self):
        return max(self.credits) if self.credits else float('-inf')


@dataclass
class Slot:
    original: str
    kind: str                     # 'related' (itself + neighbours), 'random' (itself + 4 random), 'fixed' (itself only)
    choices: list


class Evolver:
    """Holds the swap pool and the knowledge graph for one upload."""

    def __init__(self, user_rows, library_rows=None):
        lib = _library_rows() if library_rows is None else library_rows
        user_hashes = {r['Hash'] for r in user_rows}
        # a blank Signature_ID arrives as 'nan' (pandas) or '' (upload parser); treat both as the blank id 'nan'
        blank = lambda r: dict(r, Signature_ID='nan') if str(r['Signature_ID']).strip() in ('', 'nan', 'None') else r
        self.rows = [blank(r) for r in [r for r in lib if r['Hash'] not in user_hashes] + list(user_rows)]
        self.by_ss = {}
        for r in self.rows:
            self.by_ss.setdefault((r['Hash'], r['Signature_ID']), []).append(r)
        self.donors = {}
        for (h, s) in self.by_ss:
            self.donors.setdefault(s, []).append(h)
        self.pool = sorted(s for s in self.donors if s != 'nan')
        by_tag = {}
        for s, ts in TAGS.items():
            for t in ts:
                by_tag.setdefault(t, set()).add(s)
        pool = set(self.pool)
        self.neighbors = {s: sorted((set().union(*[by_tag[t] for t in ts]) - {s}) & pool) for s, ts in TAGS.items()}

    # ---- building an attack ----
    def original(self, h):
        return list(dict.fromkeys(r['Signature_ID'] for r in self.rows if r['Hash'] == h))

    def slots(self, h, rng):
        """One slot per original signature. A slot never offers another slot's original signature,
        so two slots can never hold the same signature through their originals."""
        orig = self.original(h)
        taken = set(orig)
        out = []
        for s in orig:
            if s == 'nan' or s not in self.donors:
                out.append(Slot(s, 'fixed', [Choice(s)]))
                continue
            nbrs = [x for x in self.neighbors.get(s, []) if x not in taken]
            if nbrs:
                out.append(Slot(s, 'related', [Choice(s)] + [Choice(x) for x in nbrs]))
            else:
                free = [x for x in self.pool if x not in taken]
                pick = rng.sample(free, min(N_RANDOM_CHOICES, len(free)))
                out.append(Slot(s, 'random', [Choice(s)] + [Choice(x) for x in pick]))
        return out

    def attack_rows(self, h, attack_sigs, borrowed, rng):
        """The sample's own rows for its original signatures + rows borrowed (relabelled to this sample)
        from one donor sample for a swapped-in signature. The donor is drawn once per signature per run."""
        out = []
        for s in attack_sigs:
            if (h, s) in self.by_ss:
                out += self.by_ss[(h, s)]
            else:
                donor = borrowed.setdefault(s, rng.choice(self.donors[s]))
                for i, r in enumerate(self.by_ss[(donor, s)]):
                    rr = dict(r)
                    rr['Hash'] = h
                    rr['Candidate_ID'] = 'X%s_%d' % (s, i)
                    out.append(rr)
        return out

    def defense(self, h, attack_sigs, borrowed, rng, seed):
        rows = self.attack_rows(h, attack_sigs, borrowed, rng)
        with _LOCK:
            return core.run_ccea_for_sample(h, rows, seed=seed)

    # ---- the attack CCEA (same selection rules as the defense) ----
    @staticmethod
    def select(slot, rng):
        unexplored = [c for c in slot.choices if c.tried == 0]
        if unexplored:
            return rng.choice(unexplored)
        if rng.random() < core.EXPLORATION_PROBABILITY:
            return rng.choice(slot.choices)
        return max(slot.choices, key=lambda c: (c.mean, c.best))

    @staticmethod
    def mutate(slot, picked, rng):
        if len(slot.choices) <= 1 or rng.random() >= core.MUTATION_PROBABILITY:
            return picked
        return rng.choice([c for c in slot.choices if c is not picked])

    def build_attack(self, slots, rng):
        used, picks = set(), []
        for slot in slots:
            c = self.mutate(slot, self.select(slot, rng), rng)
            if c.sig in used:                         # another slot already took it: keep this slot's own signature
                c = slot.choices[0]
            used.add(c.sig)
            picks.append(c)
        return picks

    def evolve_attack(self, h, seed, progress=None):
        rng = random.Random(seed)
        slots = self.slots(h, rng)
        borrowed = {}
        orig = [s.original for s in slots]

        r0 = self.defense(h, orig, borrowed, rng, seed)           # iteration 1: the original sample
        for s in slots:
            s.choices[0].credits.append(1 - r0['best_fitness_full'])
        best = dict(generation=0, F=r0['best_fitness_full'], attack=orig, result=r0)
        defenses = [(0, best['F'], r0)]
        found_cache = {}
        hist = [dict(generation=0, F=best['F'], best_F=best['F'], improved=True, changed=0,
                     repo_found=self._count_found(orig, orig, found_cache))]
        no_improve, stopped_by, gen = 0, 'max_generations', 0
        for gen in range(1, core.MAX_GENERATIONS + 1):
            picks = self.build_attack(slots, rng)
            attack = [c.sig for c in picks]
            res = self.defense(h, attack, borrowed, rng, seed)
            F = res['best_fitness_full']
            for c in picks:
                c.credits.append(1 - F)                    # credit sharing: every choice that took part
            improved = F < best['F'] - core.MIN_IMPROVEMENT
            if improved:
                best = dict(generation=gen, F=F, attack=attack, result=res)
                defenses.append((gen, F, res))
                no_improve = 0
            else:
                no_improve += 1
            hist.append(dict(generation=gen, F=F, best_F=best['F'], improved=improved,
                             changed=sum(a != b for a, b in zip(orig, attack)),
                             repo_found=self._count_found(orig, best['attack'], found_cache)))
            if progress:
                progress(gen)
            if no_improve >= core.PATIENCE and all(c.tried for s in slots for c in s.choices):
                stopped_by = 'patience'
                break
        return dict(slots=slots, best=best, hist=hist, defenses=defenses, stopped_by=stopped_by,
                    generations=gen, borrowed=borrowed)

    # ---- held-out check against the public repository ----
    def found_in_repo(self, original, final, show=5):
        """Real samples (MLRan, never used to build the attack) whose whole signature list is inside the
        evolved attack and that use at least one swapped-in signature, so they are there because of the evolution."""
        orig = {ID2NAME[s] for s in original if s in ID2NAME}
        fin = {ID2NAME[s] for s in final if s in ID2NAME}
        new = fin - orig
        hits = [(f, l) for f, l in REF if l <= fin and l & new]
        fams = sorted({f for f, _ in hits})
        return dict(found=bool(hits), n_samples=len(hits), families=fams, n_families=len(fams),
                    n_before=sum(1 for _, l in REF if l <= orig), repo_url=REPO_URL, repo_size=REPO_SIZE,
                    examples=self._examples(hits, new, show))

    @staticmethod
    def _examples(hits, new, show):
        """Real samples grouped by identical signature list (one line per list, with every family that has it),
        largest lists first."""
        groups = {}
        for f, l in hits:
            groups.setdefault(l, set()).add(f)
        top = sorted(groups.items(), key=lambda x: (-len(x[0]), -len(x[1]), sorted(x[1])))[:show]
        return [dict(families=sorted(fs), samples=sum(1 for f, l in hits if l == sig), signatures=sorted(sig),
                     new_signatures=sorted(sig & new)) for sig, fs in top]

    def _count_found(self, original, final, cache):
        key = tuple(final)
        if key not in cache:
            cache[key] = self.found_in_repo(original, final, show=0)['n_samples']
        return cache[key]


def sample_seed(h, seed_run=0):
    """Notebook rule: 1000*seed_run + int(Hash) % 1000 (crc32 for non-numeric hashes)."""
    try:
        base = int(h) % 1000
    except ValueError:
        base = zlib.crc32(str(h).encode()) % 1000
    return 1000 * seed_run + base


def _combo(res):
    return {str(d['signature_id']): d for d in res['optimal_combination']}


def _dname(d):
    return DEF_NAME.get(str(d['defense_id']), str(d['defense_id']))


def evolve_sample(ev: Evolver, h, seed_run=0, progress=None):
    """Evolve one sample's attack and return a JSON-ready dict."""
    seed = sample_seed(h, seed_run)
    run = ev.evolve_attack(h, seed, progress)
    slots, best, defenses = run['slots'], run['best'], run['defenses']
    original = [s.original for s in slots]
    final = best['attack']
    first, last = _combo(defenses[0][2]), _combo(defenses[-1][2])

    table = []
    for sig, d in last.items():
        before = first.get(sig)
        status = 'new signature' if before is None else ('same' if str(before['defense_id']) == str(d['defense_id']) else 'changed')
        table.append(dict(signature_id=sig, signature=ID2NAME.get(sig, sig),
                          defense_before=None if before is None else _dname(before),
                          defense_after=_dname(d), status=status))
    order = {'new signature': 0, 'changed': 1, 'same': 2}
    table.sort(key=lambda r: (order[r['status']], r['signature']))

    kind = {s.original: s.kind for s in slots}
    swaps = [dict(old=a, old_name=ID2NAME.get(a, a), new=b, new_name=ID2NAME.get(b, b),
                  link='related' if kind[a] == 'related' else 'random') for a, b in zip(original, final) if a != b]

    def curve(res):   # the defender's own climb, generation by generation (goes up)
        return [dict(generation=g['generation'], best_F=g['best_fitness_so_far']) for g in res['generation_history']]

    return dict(
        hash=h, seed=seed, generations_run=run['generations'], stopped_by=run['stopped_by'],
        best_generation=best['generation'], improvements=len(defenses) - 1,
        F_original=defenses[0][1], F_evolved=best['F'],
        slots=dict(total=len(slots), related=sum(s.kind == 'related' for s in slots),
                   random=sum(s.kind == 'random' for s in slots), fixed=sum(s.kind == 'fixed' for s in slots),
                   choices=sum(len(s.choices) for s in slots)),
        history=[dict(generation=x['generation'], F=x['F'], best_F=x['best_F'], attack_strength=1 - x['best_F'],
                      generation_attack=1 - x['F'], improved=x['improved'], changed=x['changed'],
                      repo_found=x['repo_found']) for x in run['hist']],
        swaps=swaps,
        defense_curve_original=curve(defenses[0][2]), defense_curve_evolved=curve(defenses[-1][2]),
        defense_before_after=table,
        found_in_repo=ev.found_in_repo(original, final),
    )
