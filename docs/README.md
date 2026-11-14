# Knowledge graph of related signatures

The attack evolution swaps a signature only for a **related** one: a signature that shares a tag published by
the Malware Behavior Catalog (MBC) or MITRE ATT&CK. A signature with no related signature gets random choices instead.
The tags used are in `backend/attack_data/signature_tags.csv` (one row per signature and tag).

| File | What it is |
|---|---|
| `signature_tag_graph.png` | The graph as cards: one card per tag shared by at least two swappable signatures (31 cards). Signatures on the same card are related. The 24 signatures with no related signature are listed at the bottom. |
| `CCEA_signature_tag_graph.owl` | The same graph for Protege / WebProtege (File > Open, or upload). Individuals = signatures; `hasTag` links a signature to its tags; `relatedTo` links two signatures that share a tag. Covers the 81 swappable signatures that have a tag. |

A shared tag is a loose link, so signatures are called related, never equivalent.

Sources: MBC community repository (branch `mbc-cuckoo`) https://github.com/MBCProject/community ;
MITRE ATT&CK data https://github.com/mitre-attack/attack-stix-data .
