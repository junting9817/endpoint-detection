# Analysis workflow

The checklist for every technique, from picking a dataset to a validated rule. Work top to bottom.
Scripts are marked with the phase that delivers them; until one exists, the manual command is shown.

**Conventions**

```bash
CASE=2026-09-20-empire-launcher-vbs     # analyses/<CASE>/, one dataset per case
CH() { docker exec -i nsm-clickhouse clickhouse-client "$@"; }   # the lab's container, database ep
```

- All times are **UTC**. Windows records `@timestamp` in UTC already; keep it that way in queries and reports.
- Nothing from a dataset is executed, reconstructed or contacted. These are recordings.
- Quote the log, do not paraphrase it: a command line in a report should be the command line in the event.

---

## 0. Ground rules

- [ ] The dataset is someone else's lab recording. It may contain their host names, user names and paths — use them as
      evidence, never invent or tidy them.
- [ ] Only `ep.*` tables are written. The NSM lab's `nsm` database is never modified (CLAUDE.md D2).
- [ ] Downloads come from the dataset repositories only.

## 1. Pick a technique

- [ ] Choose a technique worth a rule: one where the *behaviour* is distinctive, not just the file name.
      Good first candidates: encoded PowerShell, Office spawning a shell, service installation, LSASS access,
      scheduled-task persistence, WMI execution.
- [ ] Find a dataset for it:
  - Security-Datasets: `datasets/atomic/windows/<tactic>/host/<name>.zip`, described in
    `datasets/atomic/_metadata/SDWIN-*.yaml` (each metadata file names the ATT&CK technique and how the data was made).
  - EVTX-ATTACK-SAMPLES: `.evtx` files named by technique (Phase 2 adds EVTX support).
- [ ] Note what the dataset claims to contain. That claim is a starting point, not a finding: confirm it in the events.

## 2. Fetch and load — `scripts/fetch-dataset.sh`, `scripts/load-dataset.sh`

- [ ] `scripts/new-case.sh <case>` creates the case folder and `report.md` from the template.
- [ ] `scripts/fetch-dataset.sh <path-or-url>` downloads to `datasets/`, checks the archive and records both hashes
      in `source.txt`. Only the dataset repositories are accepted as download hosts.
- [ ] `scripts/load-dataset.sh <dataset id> $CASE` maps the events into `ep.win_events` (one partition per dataset, so
      re-loading replaces rather than duplicates), refreshes `ep.datasets`, and writes `analyses/$CASE/dataset.txt`.
      Process creation is normalised: Sysmon 1 and Security 4688 both fill `image`, `command_line`, `parent_image`
      and `user`, and every unmapped field is kept in the `extra` map.
- [ ] Sanity-check what arrived:

  ```sql
  SELECT channel, event_id, count() FROM ep.win_events WHERE dataset = '<id>' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20;
  SELECT min(ts), max(ts), uniq(hostname) FROM ep.win_events WHERE dataset = '<id>';
  ```

## 3. Triage — `scripts/summarize.py` (Phase 3)

- [ ] `scripts/summarize.py $CASE` writes `triage.txt`: event counts by channel and EventID, the process tree, rare
      parent-child pairs, command lines containing encoded or obfuscated content, LOLBin execution, per-process network
      connections, registry and service changes, and log clearing.
- [ ] Read it before writing any query. The tree usually shows the whole attack in ten lines.

## 4. Follow the process tree

- [ ] Start from the earliest suspicious process create (Sysmon 1) and walk both ways: what started it, what it started.

  ```sql
  SELECT ts, process_guid, parent_image, image, command_line, user
  FROM ep.win_events WHERE dataset = '<id>' AND event_id = 1 ORDER BY ts;
  ```
- [ ] For each interesting process, pull everything it did:

  ```sql
  SELECT ts, event_id, image, target_filename, destination_ip, destination_port, details
  FROM ep.win_events WHERE dataset = '<id>' AND process_guid = '<guid>' ORDER BY ts;
  ```
- [ ] Ask of every step: what would this look like on a normal workstation? That question is the rule.

## 5. Check the other channels

| Looking for | Where |
|---|---|
| Process creation, network, file, registry, image load | Sysmon 1, 3, 11, 12–14, 7 |
| Process access (credential theft) | Sysmon 10 (`LSASS` as target) |
| Service installation | Security 4697, System 7045 |
| Scheduled tasks | Security 4698–4702 |
| Logons and privilege use | Security 4624, 4625, 4672, 4648 |
| PowerShell script blocks | Microsoft-Windows-PowerShell/Operational 4104 |
| Log clearing | Security 1102, System 104 |

## 6. Decide what to detect

- [ ] Rank the candidate signals by how much an attacker would have to change to evade them:
      parent-child relationship and API behaviour survive most changes; command-line strings survive some; file names
      and hashes survive none.
- [ ] Write down explicitly what benign software does that looks similar. If you cannot name it, you have not
      understood the signal yet.

## 7. Write the rule — `rules/sigma/<id>.yml`

- [ ] Sigma format, one rule per file:

  ```yaml
  title: <short, specific>
  id: <uuid>
  status: experimental
  description: <what it detects and why that is suspicious>
  references: [<dataset url>]
  author: junting9817
  date: YYYY-MM-DD
  logsource: {product: windows, category: process_creation}
  detection:
    selection: {ParentImage|endswith: '\winword.exe', Image|endswith: '\powershell.exe'}
    condition: selection
  falsepositives: [<the legitimate case you named in step 6>]
  level: high
  tags: [attack.execution, attack.t1059.001]
  ```
- [ ] Add the entry to [rules/README.md](../rules/README.md) **in the same commit**, including the evasion note.

## 8. Validate — `scripts/validate-rules.sh` (Phase 4)

- [ ] Add the case to `rules/expected.yaml`: which rule must fire, how many times, on which dataset.
- [ ] `scripts/validate-rules.sh` converts every rule to SQL, runs it against **every** loaded dataset, and reports
      PASS/FAIL plus false-positive candidates — a rule firing on a dataset where it was not expected.
- [ ] Datasets for other techniques are the control group: a rule for credential theft firing on a persistence dataset
      is a finding, not a coincidence. Resolve every one before moving on.

## 9. Write it up

- [ ] Fill [TEMPLATE.md](../TEMPLATE.md) sections 1–10, including the hunting queries an analyst would run on a real
      estate, and what the dataset cannot show.
- [ ] Set `status: final` only when no `<placeholder>` remains.

## 10. Publish

- [ ] `scripts/update-readme.py` (Phase 5) refreshes the index, rule table and ATT&CK coverage.
- [ ] Add the takeaways to [lessons.md](lessons.md).
- [ ] Commit checks:

  ```bash
  git status --short --ignored     # datasets must show as ignored (!!)
  git add analyses/$CASE rules docs README.md && git commit
  ```

  The pre-commit hook refuses datasets, archives, EVTX files and blobs over 5 MiB. If it blocks a commit, move the file
  out of the repository — never bypass it with `--no-verify`.
