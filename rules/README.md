# Sigma rules

Rules live in [sigma/](sigma/), one file per detection, written in Sigma so they can be converted to whatever a SOC
runs. `scripts/sigma-to-sql.py` converts them to ClickHouse SQL for validation in this repo.

Add the entry below in the same commit as the rule.

| ID | Title | ATT&CK | Log source | Source case | Status |
|---|---|---|---|---|---|
| — | No rules yet | — | — | — | — |

<!--
## <rule id> — <title>

- **Source case:** [YYYY-MM-DD-<technique>](../analyses/YYYY-MM-DD-<technique>/report.md)
- **Intent:** <the behaviour this detects, in one sentence>
- **Logic:** <fields and values, and why each one is there>
- **Why not an indicator:** <what survives a rename, a new domain, a new hash>
- **ATT&CK:** <T0000.000 name>
- **Validation:** <datasets where it must fire, and where it must stay silent>
- **False-positive notes:** <legitimate software that behaves the same way, and how to scope the rule>
- **Evasion notes:** <what an attacker would change to slip past it>
-->
