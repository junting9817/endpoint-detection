# Lessons learned

One entry per technique, newest first. Record what changed how I analyse or detect — not a summary of the report.

<!--
## YYYY-MM-DD-<technique>

- **Analysis:** <what the raw events did not show, which query made it obvious>
- **Detection:** <why the rule keys on what it does; what a real attacker could change to evade it>
- **False positives:** <where it fired when it should not, and the fix (rule id + version)>
- **Next time:** <one concrete change to docs/workflow.md or the scripts>
-->

## 2026-09-16-empire-launcher-vbs

- **Analysis:** the process tree and the command line told me what started; they said nothing about what the stager did
  for the next 47 seconds, because it never created another process. Module logging (4103) did — extracting
  `CommandInvocation(...)` out of `extra['Payload']` produced the WMI fingerprinting and the 5-second `Start-Sleep`
  loop, which is the beacon. **Script block logging (4104) stopped after one event while module logging carried on**,
  which is the reverse of how I had been prioritising the two channels. When 4104 is quiet, 4103 is where the
  intrusion still is.
- **Analysis:** that one 4104 event is severity `WARNING` — Windows' automatic logging of script blocks it finds
  suspicious, which happens whether or not the policy is on. So "a single WARNING-level 4104 with no ordinary 4104
  traffic around it" is itself a signal; and I cannot conclude from telemetry alone that the stager's tamper is what
  silenced the channel, because the policy may never have been enabled. Both readings lead to the same recommendation.
- **Detection:** `powershell-amsi-and-logging-tamper` keys on the .NET field names the technique has to reference
  (`amsiInitF`, `AmsiUtils`, `cachedGroupPolicySettings`, `EnableScriptB`), truncated where this sample splits the
  strings so it matches the split and unsplit spellings alike — not on Empire's obfuscation, which differs per build,
  and not on the C2 address, which is base64 *inside* the base64 command: searching command lines for the IP finds
  nothing. Evasion: an attacker who only reads those fields, or reaches them through a computed name, is not caught.
- **False positives:** none in validation, but with two recordings that proves very little. What the triage *did*
  mislabel: the `__PSScriptPolicyTest_*.ps1` files PowerShell creates and deletes appear under "files deleted by their
  creator" and read like cleanup — they are PowerShell's own script-policy probes. Handled with a note in the report
  rather than a change to `summarize.py`, since that section is deliberately raw.
- **Tooling:** two defects this case exposed, one fixed and one recorded.
  - Fixed: `scripts/lib/win_events.py` discarded `ExecutionProcessID`, so every PowerShell 4103/4104 row had
    `process_id = 0` and could not be joined back to the process that produced it. It is now the last fallback for
    `process_id`, after the real fields, and 4103/4104 resolve to pid 2316. Both datasets reloaded, validation still
    `PASSED`, `triage.txt` byte-identical.
  - Recorded, not fixed: `ts` is the collector's `@timestamp`, which runs 1–3 seconds *after* Sysmon's own `UtcTime`,
    by a different amount per event. Ordering within a channel is safe; sub-second ordering between channels is not.
    Reports state this from here on, and no conclusion may rest on a cross-channel gap of less than a few seconds. A
    `ts_event` column holding the producer's own time is the real fix, for a later phase.
- **Next time:** before writing the timeline, run the cmdlet-extraction query over 4103 — one query, and it is the only
  view of what an in-memory agent did. Worth a section in `summarize.py` so the triage shows it without being asked.
