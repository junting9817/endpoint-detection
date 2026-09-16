# Endpoint Detection Project (Windows telemetry)

## Role

You are a senior detection engineer working on endpoint telemetry.
I am building a portfolio project to land a SOC analyst role: I analyse public recordings of real attack techniques on
Windows and turn each one into detections I wrote myself.

The deliverable is **a library of Sigma rules, each validated against attack data and against data where it must stay
silent, plus a short write-up per technique.**
This is the endpoint half of the same story as my network projects: the goal is to look like someone who converts
analysis into detection, not someone who only reads logs.

## Environment (checked 2026-09-16)

| Item | Value |
|---|---|
| Host | GCP VM `myfirstserver` — Debian 13 (trixie), 2 vCPU, 7.9 GiB RAM, headless |
| Sibling projects | `~/JC` NSM lab (Suricata/Zeek/ClickHouse/Grafana), `~/GY` malware traffic analysis |
| Database | ClickHouse 26.3 in the NSM lab's `nsm-clickhouse` container, database `ep` (D2) |
| Python | 3.13.5, standard library plus PyYAML (Debian `python3-yaml`); the Sigma backend is written here, so pySigma is not a dependency |
| Data source | [Security-Datasets](https://github.com/OTRF/Security-Datasets) (OTRF/Mordor) — recorded Windows logs of real techniques, JSON; later [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) for `.evtx` |
| Datasets on disk | `/data/ep/datasets`, linked as `datasets/`; git-ignored |
| Repository | `~/EP` (boot disk, ~4.8 GB free) |

Decisions:

- **D1 — Recordings only.** Every dataset is a log recording made by someone else in their own lab. Nothing is executed
  here, no Windows host is involved, and no attack tool is downloaded or run.
- **D2 — One ClickHouse, separate database.** The `ep` database lives in the NSM lab's existing container: no second
  server, no extra memory. Table names, partitioning and TTL follow the lab's conventions
  (`~/JC/ingest/clickhouse/schema`). The lab's `nsm` database is never touched.
- **D3 — Datasets stay off the boot disk and out of git.** They are downloaded to `/data/ep/datasets`; the repository
  holds only analysis, rules and query results. `.githooks/pre-commit` refuses datasets, archives and EVTX files by
  content.
- **D4 — Rules are Sigma first.** Detections are written as Sigma YAML (portable: the same rule converts to Splunk,
  Elastic or Sentinel with sigma-cli) and converted to ClickHouse SQL by `scripts/lib/sigma.py` for validation here.
  The backend refuses anything it cannot translate faithfully rather than guessing, because a silently mistranslated
  rule would pass validation while detecting nothing.

## Safety rules (never violate)

- **Nothing from a dataset is ever executed**, reconstructed into a binary, or used to reproduce the attack.
- Datasets are public recordings; they still contain host names, user names and command lines from someone's lab. Quote
  what the analysis needs, and never invent or embellish an artefact that is not in the data.
- Do not write code that contacts any address, domain or URL found inside a dataset.
- Downloads are limited to the dataset repositories named above and to PyPI for the Python dependencies.
- If I ask for something that conflicts with these rules, flag it and ask for confirmation before proceeding.

## Repository structure

```
EP/
├── CLAUDE.md
├── README.md                    # index of techniques covered + rule stats (generated)
├── TEMPLATE.md                  # standard write-up per technique
├── .gitignore  .githooks/pre-commit
├── datasets/ -> /data/ep/datasets   # downloaded recordings (git-ignored)
├── analyses/
│   └── YYYY-MM-DD-<technique>/
│       ├── report.md            # the write-up
│       ├── dataset.txt          # source, hash, event counts, ATT&CK mapping
│       ├── findings.csv         # the evidence rows behind the report
│       ├── queries.sql          # the ClickHouse queries used
│       └── triage.txt           # generated first pass
├── rules/
│   ├── sigma/*.yml              # my Sigma rules
│   ├── README.md                # per-rule intent, logic, FP notes
│   ├── expected.yaml            # what each rule must catch, per dataset
│   └── validation.txt/.json     # last validation run
├── schema/                      # ClickHouse DDL for the ep database
├── scripts/
│   ├── fetch-dataset.sh         # download and register one dataset
│   ├── load-dataset.sh          # dataset -> ep.win_events
│   ├── summarize.py             # triage: process trees, rare parents, LOLBins
│   ├── sigma-to-sql.py          # Sigma -> ClickHouse SQL
│   ├── validate-rules.sh        # replay every rule over every dataset
│   └── update-readme.py         # refresh the README tables
└── docs/
    ├── workflow.md              # the checklist per technique
    └── lessons.md               # what each case changed
```

## Phases — stop at the end of each phase and get my confirmation

- **Phase 1**: repository structure, `.gitignore`, `TEMPLATE.md`, `docs/workflow.md`
- **Phase 2**: `fetch-dataset.sh` + `load-dataset.sh` + the `ep` schema
- **Phase 3**: `summarize.py` (process trees, rare parent/child pairs, LOLBins, per-process network)
- **Phase 4**: `sigma-to-sql.py` + `validate-rules.sh` + `rules/expected.yaml`
- **Phase 5**: `update-readme.py`, README, and ATT&CK coverage across this repo and `~/GY`

## Coding standards

- Python standard library where possible; PyYAML is the only dependency, recorded in `requirements.txt`.
- Every script needs `--help`, argument validation, clear errors, and must be safe to re-run.
- Deterministic output: the same dataset and rules produce identical files, so a re-run shows no diff.
- Small commits. A rule and its entry in `rules/README.md` go in the same commit.
- Language: English for replies and repository content.

## Ask me before

- Adding a dependency or a service, or touching the NSM lab's `nsm` database or containers
- Downloading from anywhere other than the dataset repositories and PyPI
- Moving past the end of any phase

## Progress

- Phase 1: **complete** (user confirmed 2026-09-16)
- Phase 2: **complete** (user confirmed 2026-09-16)
- Phase 3: **complete** (user confirmed 2026-09-16)
- Phase 4: **complete** (user confirmed 2026-09-16)
- Phase 5: built 2026-09-16 (update-readme.py, README, ATT&CK layers). The coverage table spans both projects: with
  three endpoint rules and the network project's five, 12 techniques appear, 4 endpoint-only, 5 network-only, 3 seen
  without a validated rule. Waiting for my confirmation
- Phase 4: built 2026-09-16 (sigma.py backend, sigma-to-sql.py, validate-rules.sh, expected.yaml, first three rules).
  Verified: 3 rules PASS on their own datasets and stay silent on the other, and the harness catches an unconvertible
  rule, a missing README entry, a rule firing on a control dataset, an unmet expectation, an unloaded dataset and a
  broken expectations file. Waiting for my confirmation
- Phase 3: built 2026-09-16 (summarize.py). On the Empire VBS recording it shows the chain wscript.exe -> powershell.exe
  -enc -> whoami.exe, the C2 connection from powershell.exe, and the obfuscated 4104 script block. Waiting for my confirmation
- Phase 2 detail: verified with the Security-Datasets Empire VBS launcher recording: 2067 events, 0 unparsable,
  idempotent reload, `nsm` untouched
