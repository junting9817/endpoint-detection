# Sigma rules

Rules live in [sigma/](sigma/), one file per detection, written in Sigma so they can be converted to whatever a SOC
runs. `scripts/sigma-to-sql.py` converts them to ClickHouse SQL for validation in this repo.

Add the entry below in the same commit as the rule.

| ID | Title | ATT&CK | Log source | Source case | Status |
|---|---|---|---|---|---|
| `script-host-spawns-powershell` | Script host starts PowerShell | T1059.001, T1059.005 | process_creation | empire_launcher_vbs | experimental |
| `encoded-powershell-command` | PowerShell started with an encoded command | T1059.001, T1027 | process_creation | empire_launcher_vbs | experimental |
| `lsass-memory-read-access` | LSASS opened with memory read access | T1003.001 | process_access | cmd_lsass_memory_dumpert_syscalls | experimental |

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

## Script host starts PowerShell

- **Source dataset:** `empire_launcher_vbs` (Security-Datasets, execution)
- **Intent:** catch a script file handing over to PowerShell — the shape of a launcher, whatever the script contains.
- **Logic:** process creation whose parent is `wscript.exe` or `cscript.exe` and whose image is PowerShell.
- **Why not an indicator:** no file name, hash or domain appears in the rule. The delivery script can be rewritten
  completely and the relationship stays.
- **ATT&CK:** T1059.001 PowerShell, T1059.005 Visual Basic
- **Validation:** fires on `empire_launcher_vbs`; silent on the credential-access recording.
- **False-positive notes:** administrative VBScript wrappers do this on purpose. Allowlist by script path, not by
  disabling the rule.
- **Evasion notes:** an attacker can have the script call PowerShell indirectly (through WMI, a scheduled task, or
  `cmd.exe`), which breaks the parent-child link. Pair it with the encoded-command rule rather than relying on it alone.

## PowerShell started with an encoded command

- **Source dataset:** `empire_launcher_vbs`
- **Intent:** catch the command-line shape that launchers use to carry a script past quoting and logging.
- **Logic:** PowerShell process creation whose command line contains `-enc`, `-encodedcommand`, `-ec` or `/enc`.
- **Why not an indicator:** it matches the invocation, not the payload. The encoded blob changes per campaign.
- **ATT&CK:** T1059.001 PowerShell, T1027 Obfuscated Files or Information
- **Validation:** fires on `empire_launcher_vbs`; silent on the credential-access recording.
- **False-positive notes:** some deployment and backup products encode their own scripts. Allowlist by parent process.
- **Evasion notes:** `-e`, `-en` and other prefixes of `-EncodedCommand` are valid PowerShell and are not matched by
  this rule; extending the list costs false positives (`-ExecutionPolicy` also starts with `-e`). Script block logging
  (4104) catches what the command line hides, which is why both are collected.

## LSASS opened with memory read access

- **Source dataset:** `cmd_lsass_memory_dumpert_syscalls` (Security-Datasets, credential access)
- **Intent:** catch credential dumping at the moment it needs LSASS memory, regardless of the tool.
- **Logic:** Sysmon 10 where the target is `lsass.exe` and the granted access is one of the masks that permit reading
  memory (0x1fffff, 0x1f0fff, 0x1010, 0x1410, 0x1438, 0x143a), excluding a few system processes that do it routinely.
- **Why not an indicator:** the tool in the source dataset (`Outflank-Dumpert.exe`) never appears in the rule; renaming
  or rewriting it changes nothing.
- **ATT&CK:** T1003.001 LSASS Memory
- **Validation:** fires on `cmd_lsass_memory_dumpert_syscalls`; silent on the execution recording.
- **False-positive notes:** endpoint protection and backup agents read process memory legitimately. Allowlist those
  images by full path — a name-only allowlist is trivially abused by dropping a file with that name elsewhere.
- **Evasion notes:** an attacker can request a narrower mask and still read memory (0x1010 is included for that
  reason), or avoid the API entirely by dumping via a driver or a snapshot. The call trace field is where those show
  up; this rule does not cover them.
