---
title: <Technique> — <what the attacker did, in a few words>
date: YYYY-MM-DD
technique: <family or tool name, e.g. Empire launcher>
dataset: <Security-Datasets path or EVTX-ATTACK-SAMPLES file>
summary: <one line for the README index>
attack: T0000, T0000.000
rules: <rule ids you wrote for this case, comma separated>
status: draft
---

<!--
How to use this template
- scripts/new-case.sh copies it to analyses/YYYY-MM-DD-<technique>/report.md (Phase 2).
- The front matter is read by scripts/update-readme.py (Phase 5): one `key: value` per line, lists comma-separated.
  `status` is draft or final; only final write-ups count in the README totals.
- Every claim cites evidence: an event (channel + EventID + record) or the query that produced the rows.
- Safety: nothing is executed. The dataset is a recording; quote it, never reproduce the attack.
- Delete these comments and every <placeholder> before setting status: final.
-->

# <Technique> — <what the attacker did>

## 1. Executive summary

<!-- Three lines: what happened on the host, what gives it away, what to do about it. -->

- **What:** <user/host> ran <what>, which led to <outcome>.
- **Detection:** <the behaviour that exposes it>, covered by <rule ids>; the noisy alternative would be <what not to key on>.
- **Action:** <containment and the control that prevents a repeat>.

## 2. Dataset

| Field | Value |
|---|---|
| Source | [<repository> <path>](<url>) |
| Archive | `<name>.zip` — SHA256 `<hash>` |
| Events | <n> events, <n> Sysmon, <n> Security |
| Time range (UTC) | <first> → <last> (<duration>) |
| Hosts | <hostname(s)>, <user(s)> |
| ATT&CK (claimed by the dataset) | <T0000> |
| Loaded as | `ep.win_events` partition `<dataset id>` — see [dataset.txt](dataset.txt) |

## 3. What happened

<!-- The attack in order. One row per event that matters; leave out the noise. -->

| Time (UTC) | Event | Detail | Evidence |
|---|---|---|---|
| HH:MM:SS | Process create | `<parent>` → `<child>` `<command line>` | Sysmon 1, record <n> |
| HH:MM:SS | <network / file / registry> | <detail> | <channel + EventID> |

## 4. Process tree

```
<parent.exe>  (pid)
└── <child.exe>  (pid)   <command line>
    └── <grandchild.exe>  (pid)
```

<!-- The tree is the endpoint equivalent of a network timeline: it shows intent, not just activity. -->

## 5. Evidence per stage

| Stage | What the logs show | Where |
|---|---|---|
| Execution | <command line, interpreter, encoding> | Sysmon 1 |
| Persistence | <registry key, service, scheduled task> | Sysmon 12/13, Security 4697 |
| Network | <process, destination, port> | Sysmon 3 |
| Cleanup | <log clearing, file deletion> | Security 1102, Sysmon 23 |

## 6. Detection opportunities

<!-- Rank what the data offers, from most durable to most brittle, and say why. -->

| Signal | Durability | Note |
|---|---|---|
| <parent-child relationship> | high | survives renaming and re-packing |
| <command-line structure> | medium | attacker can reorder or obfuscate |
| <file path or name> | low | trivially changed — use as context, not as the rule |

## 7. My rules

| ID | Title | Fires on | Stays silent on |
|---|---|---|---|
| <id> | <title> | <dataset> (<n> hits) | <other datasets> |

```yaml
<the rule, or the part that matters>
```

**validate-rules.sh result** (full report in [rules/validation.txt](../../rules/validation.txt))

```
<paste the PASS/FAIL table and the false-positive candidates>
```

## 8. ATT&CK mapping

| Tactic | Technique | Evidence | Detected by |
|---|---|---|---|
| <tactic> | <T0000.000 name> | <event> | <rule id / not detected> |

## 9. Hunting queries

<!-- The queries an analyst would run on a real estate, not just on this dataset. -->

```sql
-- <what this finds>
SELECT ... FROM ep.win_events WHERE ...
```

## 10. Limitations and response

- **The dataset does not show:** <what is missing — no EDR context, no user intent, one host only, no benign baseline>
- **Response:** <containment, eradication, and the control that would have prevented or exposed this earlier>

**Lessons:** <one or two lines; details in [docs/lessons.md](../../docs/lessons.md)>
