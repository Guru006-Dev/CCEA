# Attack evolution data

Used by `attack_evolution.py`. Copied from `attack_evolution/` (see the scripts there for how they were built).

| File | What it is | Source |
|---|---|---|
| `signature_tags.csv` | MBC behaviour ids and MITRE ATT&CK technique ids per Cuckoo signature (the tag `E1478`, a revoked technique, is left out). Two signatures are related if they share a tag. | Malware Behavior Catalog community repo, branch `mbc-cuckoo` (https://github.com/MBCProject/community); MITRE ATT&CK STIX data (https://github.com/mitre-attack/attack-stix-data) |
| `reference_ransomware_signature_sets.csv` | 2,330 real ransomware samples (64 families), one row per sample with the list of Cuckoo signatures it triggered. The evolved attack is compared against these. | MLRan dataset, Onwuegbuche et al. 2026, https://zenodo.org/records/23403681, licence CC-BY 4.0 |

## Credit

The reference samples are derived from the MLRan dataset (Onwuegbuche et al., 2026), used under the Creative Commons Attribution 4.0 licence. Only the signature lists are kept; no malware files are included.
MBC is maintained by the MBC Project; ATT&CK is a trademark of The MITRE Corporation.
