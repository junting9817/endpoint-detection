#!/usr/bin/env python3
"""First-pass triage of one loaded dataset: where to look before writing any query (docs/workflow.md step 3).

Sections: what was recorded, the process tree, parent-child pairs (with how many other datasets share them), command
lines worth reading, LOLBin execution, network connections per process, persistence, credential access, defence
evasion, PowerShell script blocks, and a ClickHouse query for each lead.

Writes analyses/<case>/triage.txt (identical on every run for the same data) and prints it.
Reads the ep database only; makes no network requests.
"""
import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
from chquery import QueryError, query  # noqa: E402

# Event ids worth naming in the output; everything else is shown by number
EVENT_NAMES = {
    1: "process create", 2: "file creation time changed", 3: "network connection", 5: "process terminated",
    6: "driver loaded", 7: "image loaded", 8: "remote thread", 9: "raw disk access", 10: "process access",
    11: "file created", 12: "registry key created/deleted", 13: "registry value set", 14: "registry key renamed",
    15: "alternate data stream", 17: "pipe created", 18: "pipe connected", 19: "WMI filter", 20: "WMI consumer",
    21: "WMI binding", 22: "DNS query", 23: "file delete", 25: "process tampering", 26: "file delete detected",
    1102: "audit log cleared", 4624: "logon", 4625: "failed logon", 4648: "logon with explicit credentials",
    4656: "handle requested", 4658: "handle closed", 4663: "object access", 4672: "special privileges",
    4688: "process create (Security)", 4697: "service installed", 4698: "scheduled task created",
    4699: "scheduled task deleted", 4702: "scheduled task updated", 4720: "user account created",
    4732: "member added to local group", 5140: "network share accessed", 5156: "connection allowed",
    7045: "service installed (System)", 4103: "PowerShell module logging", 4104: "PowerShell script block",
    800: "PowerShell pipeline", 104: "event log cleared",
}
# Binaries that ship with Windows and are routinely abused to run or fetch code
LOLBINS = {
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe",
    "installutil.exe", "cmstp.exe", "curl.exe", "wscript.exe", "cscript.exe", "forfiles.exe", "mavinject.exe",
    "odbcconf.exe", "schtasks.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "csc.exe", "pcalua.exe",
    "hh.exe", "ieexec.exe", "presentationhost.exe", "msdt.exe", "control.exe", "scriptrunner.exe",
}
# Command-line shapes worth a human read, with why each one matters
COMMAND_PATTERNS = [
    (re.compile(r"-enc(odedcommand)?\b|\bfrombase64string\b", re.I), "encoded PowerShell"),
    (re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bwget\b|\bcurl\b|bitstransfer", re.I),
     "download cradle"),
    (re.compile(r"-nop\b|-noprofile|-w\s+hidden|-windowstyle\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass", re.I),
     "hidden or unrestricted PowerShell"),
    (re.compile(r"\^|`|\+\s*\"|\bchar\[\]|\[char\]", re.I), "obfuscation characters"),
    (re.compile(r"\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|%temp%|%localappdata%", re.I),
     "runs from a user-writable directory"),
    (re.compile(r"\biex\b|invoke-expression|\bicm\b|invoke-command", re.I), "expression execution"),
    (re.compile(r"vssadmin|wbadmin|bcdedit|cipher\s+/w|wevtutil\s+cl", re.I), "destructive or anti-forensic command"),
]
# Registry locations that actually start or hijack code. A plain "\\Services\\" match is useless: every process reads
# Tcpip\\Parameters, so the service keys are narrowed to the values that decide what runs.
PERSISTENCE_KEYS = re.compile(
    r"\\CurrentVersion\\Run(Once)?\\|\\Winlogon\\(Shell|Userinit|Notify)|\\Image File Execution Options\\|"
    r"\\Policies\\Explorer\\Run|\\Schedule\\TaskCache\\|"
    r"\\Services\\[^\\]+\\(ImagePath|ServiceDll|Start|Parameters\\ServiceDll)$", re.I)
# Sysmon 10 access masks: the first two are routine (querying a process), the rest allow reading LSASS memory
BENIGN_LSASS_ACCESS = {"0x1000", "0x1400", "0x400", "0x100000"}


class Out:
    def __init__(self):
        self.lines: list[str] = []

    def add(self, text: str = "") -> None:
        self.lines.append(text)

    def section(self, title: str) -> None:
        self.add()
        self.add(f"## {title}")
        self.add()

    def table(self, headers: list[str], rows: list[list], right: set[int] = frozenset(), width: int = 70) -> None:
        if not rows:
            self.add("  (none)")
            return
        cells = [[clip(c, width) for c in row] for row in rows]
        widths = [max(len(h), *(len(r[i]) for r in cells)) for i, h in enumerate(headers)]

        def line(row):
            return "  " + "  ".join(str(c).rjust(widths[i]) if i in right else str(c).ljust(widths[i])
                                    for i, c in enumerate(row)).rstrip()
        self.add(line(headers))
        for row in cells:
            self.add(line(row))


def clip(text, width: int) -> str:
    text = str(text if text is not None else "")
    return text if len(text) <= width else text[: width - 1] + "…"


def base(path: str) -> str:
    return (path or "").rsplit("\\", 1)[-1].lower()


def event_label(event_id: int) -> str:
    return EVENT_NAMES.get(int(event_id), "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("case", help="case folder name under analyses/, or a dataset id with --dataset")
    parser.add_argument("--dataset", help="dataset id (default: read from analyses/<case>/dataset.txt)")
    parser.add_argument("--out", help="where to write the summary (default: analyses/<case>/triage.txt; '-' prints only)")
    parser.add_argument("--top", type=int, default=15, help="rows per ranking table (default 15)")
    parser.add_argument("--rare-pairs", type=int, default=2,
                        help="a parent-child pair seen in at most this many datasets counts as rare (default 2)")
    args = parser.parse_args()
    if args.top < 1 or args.rare_pairs < 1:
        parser.error("--top and --rare-pairs must be at least 1")

    case_dir = REPO / "analyses" / args.case
    dataset = args.dataset
    if not dataset:
        info = case_dir / "dataset.txt"
        if not info.is_file():
            print(f"summarize: error: {info} not found; run scripts/load-dataset.sh {args.case} first, "
                  "or pass --dataset", file=sys.stderr)
            return 1
        for line in info.read_text(encoding="utf-8").splitlines():
            if line.startswith("dataset: "):
                dataset = line.split(": ", 1)[1].strip()
                break
    if not dataset:
        print("summarize: error: no dataset id found in dataset.txt", file=sys.stderr)
        return 1

    try:
        text = build(dataset, args)
    except QueryError as exc:
        print(f"summarize: error: {exc}", file=sys.stderr)
        return 1

    print(text, end="")
    out = args.out or (str(case_dir / "triage.txt") if case_dir.is_dir() else "-")
    if out != "-":
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        print(f"\nwritten: {path}", file=sys.stderr)
    return 0


def build(dataset: str, args) -> str:
    o = Out()
    hints: list[str] = []
    p = {"ds": dataset}
    # Only values that come from data are passed as query parameters; the row limit is an integer from
    # argparse, inlined because this ClickHouse parses every --param_ as a string (LIMIT would fail).
    top = str(int(args.top))

    overview = query("""
        SELECT count() AS events, min(ts) AS first_ts, max(ts) AS last_ts,
               groupUniqArray(hostname) AS hosts, uniq(channel) AS channels
        FROM ep.win_events WHERE dataset = {ds:String}""", p)
    if not overview or not overview[0]["events"]:
        raise QueryError(f"no events loaded for dataset '{dataset}'")
    row = overview[0]
    o.add(f"# Triage — {dataset}")
    o.add()
    o.add(f"Events:    {row['events']} over {row['channels']} channels")
    o.add(f"Window:    {row['first_ts']} -> {row['last_ts']} (UTC)")
    o.add(f"Hosts:     {', '.join(sorted(row['hosts']))}")

    # ------------------------------------------------------------------ what was recorded
    o.section(f"What was recorded (top {args.top})")
    rows = query("""
        SELECT channel, event_id, count() AS events FROM ep.win_events WHERE dataset = {ds:String}
        GROUP BY channel, event_id ORDER BY events DESC, channel, event_id LIMIT """ + top,
                 p)
    o.table(["channel", "event id", "what it is", "events"],
            [[r["channel"], r["event_id"], event_label(r["event_id"]), r["events"]] for r in rows], right={1, 3})

    # ------------------------------------------------------------------ process tree
    o.section("Process tree (Sysmon 1, falling back to Security 4688)")
    # Aliases must not repeat a column name: ClickHouse then reports the aggregate as "found in WHERE".
    # Security 4688 carries no process GUID, so a synthetic key keeps those rows apart.
    procs = dedupe_processes(query("""
        SELECT if(process_guid != '', process_guid, concat('pid-', toString(process_id), '-', toString(ts))) AS guid,
               min(ts) AS first_ts, any(event_id) AS source_event, any(process_id) AS pid, any(image) AS exe,
               any(command_line) AS cmd, any(parent_process_guid) AS parent_guid, any(parent_image) AS parent_exe,
               any(parent_process_id) AS parent_pid, any(user) AS account
        FROM ep.win_events
        WHERE dataset = {ds:String} AND event_id IN (1, 4688) AND image != ''
        GROUP BY guid ORDER BY first_ts, guid""", p))
    o.add(f"{len(procs)} process creations.")
    o.add()
    o.add(render_tree(procs))
    for proc in procs:
        if base(proc["exe"]) in LOLBINS and proc["parent_exe"]:
            hints.append(f"LOLBin {base(proc['exe'])} started by {base(proc['parent_exe'])} at {proc['first_ts']}: "
                         f"SELECT ts, event_id, image, target_filename, destination_ip FROM ep.win_events "
                         f"WHERE dataset='{dataset}' AND process_guid='{proc['guid']}' ORDER BY ts")
            break

    # ------------------------------------------------------------------ parent-child pairs
    o.section(f"Parent -> child pairs (rare = seen in at most {args.rare_pairs} datasets)")
    pairs = query("""
        WITH pairs AS (
            SELECT dataset, lower(splitByChar('\\\\', parent_image)[-1]) AS parent,
                   lower(splitByChar('\\\\', image)[-1]) AS child,
                   process_id AS pid
            FROM ep.win_events WHERE event_id IN (1, 4688) AND image != '' AND parent_image != '')
        SELECT parent, child,
               uniqExactIf(pid, dataset = {ds:String}) AS here,
               uniqExactIf(dataset, dataset != {ds:String}) AS other_datasets
        FROM pairs GROUP BY parent, child HAVING here > 0
        ORDER BY other_datasets ASC, here DESC, parent, child LIMIT """ + top, p)
    o.table(["parent", "child", "here", "other datasets"],
            [[r["parent"], r["child"], r["here"], r["other_datasets"]] for r in pairs], right={2, 3})
    o.add()
    o.add("  'other datasets' counts the other recordings in ep.win_events with the same pair: a pair nobody else has")
    o.add("  is either the attack or something specific to this lab.")

    # ------------------------------------------------------------------ command lines
    o.section("Command lines worth reading")
    interesting = []
    for proc in procs:
        reasons = [why for pattern, why in COMMAND_PATTERNS if pattern.search(proc["cmd"] or "")]
        if reasons:
            interesting.append([proc["first_ts"], base(proc["exe"]), clip(proc["cmd"], 88), ", ".join(reasons)])
    o.table(["time (UTC)", "image", "command line", "why"], interesting[: args.top], width=90)
    if interesting:
        hints.append("Read the full command lines: SELECT ts, image, command_line FROM ep.win_events "
                     f"WHERE dataset='{dataset}' AND event_id IN (1,4688) ORDER BY ts")

    # ------------------------------------------------------------------ LOLBins
    o.section("LOLBin execution")
    lol = [[p_["first_ts"], base(p_["exe"]), base(p_["parent_exe"]) or "(no parent)", clip(p_["cmd"], 70)]
           for p_ in procs if base(p_["exe"]) in LOLBINS]
    o.table(["time (UTC)", "binary", "started by", "command line"], lol[: args.top], width=72)

    # ------------------------------------------------------------------ network
    o.section("Network connections per process (Sysmon 3)")
    net = query("""
        SELECT lower(splitByChar('\\\\', image)[-1]) AS process, destination_ip, destination_port,
               any(destination_hostname) AS hostname, count() AS connections
        FROM ep.win_events WHERE dataset = {ds:String} AND event_id = 3
        GROUP BY process, destination_ip, destination_port
        ORDER BY connections DESC, process, destination_ip LIMIT """ + top, p)
    o.table(["process", "destination", "port", "hostname", "connections"],
            [[r["process"], r["destination_ip"], r["destination_port"], r["hostname"], r["connections"]] for r in net],
            right={2, 4})
    interpreters = LOLBINS | {"powershell.exe", "pwsh.exe", "cmd.exe"}
    for r in net:
        if r["process"] in interpreters:
            hints.append(f"{r['process']} connected to {r['destination_ip']}:{r['destination_port']} — a script "
                         f"interpreter making its own connections: SELECT ts, image, command_line, destination_ip, "
                         f"destination_port FROM ep.win_events WHERE dataset='{dataset}' AND event_id=3 AND "
                         f"positionCaseInsensitive(image, '{r['process']}') > 0 ORDER BY ts")
            break

    # ------------------------------------------------------------------ persistence
    o.section("Persistence and configuration changes")
    reg = query("""
        SELECT lower(splitByChar('\\\\', image)[-1]) AS process, target_object, any(details) AS details, count() AS n
        FROM ep.win_events WHERE dataset = {ds:String} AND event_id IN (12, 13, 14) AND target_object != ''
        GROUP BY process, target_object ORDER BY n DESC, target_object LIMIT 400""", p)
    persistence = [[r["process"], clip(r["target_object"], 86), clip(r["details"], 30), r["n"]]
                   for r in reg if PERSISTENCE_KEYS.search(r["target_object"])]
    o.add("Registry keys used for persistence or execution control:")
    o.table(["process", "key", "value", "n"], persistence[: args.top], right={3}, width=88)
    services = query("""
        SELECT ts, event_id, user, coalesce(extra['ServiceName'], '') AS service,
               coalesce(extra['ServiceFileName'], extra['ImagePath'], '') AS path
        FROM ep.win_events WHERE dataset = {ds:String} AND event_id IN (4697, 7045, 4698, 4699, 4702)
        ORDER BY ts LIMIT """ + top, p)
    o.add()
    o.add("Services and scheduled tasks (Security 4697/4698/4699/4702, System 7045):")
    o.table(["time (UTC)", "event", "what it is", "user", "name/path"],
            [[r["ts"], r["event_id"], event_label(r["event_id"]), r["user"], clip(f"{r['service']} {r['path']}".strip(), 60)]
             for r in services], right={1})
    if persistence or services:
        hints.append(f"Persistence: SELECT ts, image, target_object, details FROM ep.win_events "
                     f"WHERE dataset='{dataset}' AND event_id IN (12,13,14) AND match(target_object, 'Run|Services|Winlogon')")

    # ------------------------------------------------------------------ credential access
    o.section("Credential access (Sysmon 10 against LSASS)")
    lsass = query("""
        SELECT lower(splitByChar('\\\\', source_image)[-1]) AS source, granted_access, count() AS n,
               any(substring(call_trace, 1, 60)) AS call_trace
        FROM ep.win_events
        WHERE dataset = {ds:String} AND event_id = 10 AND positionCaseInsensitive(target_image, 'lsass.exe') > 0
        GROUP BY source, granted_access ORDER BY n DESC LIMIT """ + top, p)
    o.table(["source process", "granted access", "times", "routine?", "call trace starts"],
            [[r["source"], r["granted_access"], r["n"],
              "routine" if r["granted_access"].lower() in BENIGN_LSASS_ACCESS else "READ ACCESS",
              r["call_trace"]] for r in lsass], right={2})
    o.add()
    o.add("  0x1000/0x1400 only query a process; masks such as 0x1010, 0x1410 or 0x143a allow reading its memory,")
    o.add("  which is what credential dumping needs.")
    if any(r["granted_access"].lower() not in BENIGN_LSASS_ACCESS for r in lsass):
        hints.append(f"LSASS access: SELECT ts, source_image, granted_access, call_trace FROM ep.win_events "
                     f"WHERE dataset='{dataset}' AND event_id=10 AND positionCaseInsensitive(target_image,'lsass.exe')>0")

    # ------------------------------------------------------------------ defence evasion
    o.section("Defence evasion")
    clears = query("""
        SELECT ts, channel, event_id, user, substring(message, 1, 60) AS message FROM ep.win_events
        WHERE dataset = {ds:String} AND event_id IN (1102, 104) ORDER BY ts LIMIT 10""", p)
    o.add("Log clearing (Security 1102, System 104):")
    o.table(["time (UTC)", "channel", "event", "user", "message"],
            [[r["ts"], r["channel"], r["event_id"], r["user"], r["message"].replace("\n", " ")] for r in clears], right={2})
    deletes = query("""
        SELECT lower(splitByChar('\\\\', image)[-1]) AS process, target_filename, count() AS n
        FROM ep.win_events WHERE dataset = {ds:String} AND event_id IN (23, 26) AND target_filename != ''
        GROUP BY process, target_filename ORDER BY n DESC LIMIT """ + top, p)
    o.add()
    o.add("Files deleted by the processes that created them (Sysmon 23/26):")
    o.table(["process", "file", "n"], [[r["process"], clip(r["target_filename"], 80), r["n"]] for r in deletes],
            right={2}, width=82)
    if clears:
        hints.append(f"An audit log was cleared: SELECT ts, user, message FROM ep.win_events "
                     f"WHERE dataset='{dataset}' AND event_id IN (1102,104)")

    # ------------------------------------------------------------------ PowerShell
    o.section("PowerShell script blocks (4104)")
    blocks = query("""
        SELECT ts, user, length(script_block) AS chars, substring(script_block, 1, 100) AS start
        FROM ep.win_events WHERE dataset = {ds:String} AND event_id = 4104 AND script_block != ''
        ORDER BY chars DESC LIMIT """ + top, p)
    o.table(["time (UTC)", "user", "chars", "script starts with"],
            [[r["ts"], r["user"], r["chars"], r["start"].replace("\n", " ")] for r in blocks], right={2}, width=84)
    if blocks:
        hints.append(f"Read a script block in full: SELECT script_block FROM ep.win_events "
                     f"WHERE dataset='{dataset}' AND event_id=4104 ORDER BY length(script_block) DESC LIMIT 1")

    # ------------------------------------------------------------------ hints
    o.section("Where to look next")
    if hints:
        for number, hint in enumerate(hints, 1):
            o.add(f"{number:>2}. {hint}")
    else:
        o.add("  Nothing stood out automatically; follow docs/workflow.md steps 4-6 in order.")
    o.add()
    return "\n".join(o.lines)


def dedupe_processes(rows: list[dict]) -> list[dict]:
    """One entry per process creation.

    Sysmon 1 and Security 4688 both record the same creation, and the Security copy carries no process GUID, so it
    would otherwise appear a second time as a root of the tree. Sysmon wins; a 4688 row is kept only when no Sysmon
    event covers the same pid and image within a few seconds.
    """
    sysmon = [r for r in rows if r["source_event"] == 1]
    seen = {(r["pid"], base(r["exe"])) for r in sysmon}
    kept = list(sysmon)
    for row in rows:
        if row["source_event"] != 1 and (row["pid"], base(row["exe"])) not in seen:
            kept.append(row)
    return sorted(kept, key=lambda r: (r["first_ts"], r["guid"]))


def render_tree(procs: list[dict]) -> str:
    """Indented process tree from process/parent GUIDs, with the processes whose parent is missing as roots."""
    by_guid = {p["guid"]: p for p in procs if p["guid"]}
    children: dict[str, list[dict]] = {}
    roots = []
    for proc in procs:
        parent = proc.get("parent_guid") or ""
        if parent and parent in by_guid and parent != proc["guid"]:
            children.setdefault(parent, []).append(proc)
        else:
            roots.append(proc)

    lines: list[str] = []

    def walk(proc: dict, depth: int) -> None:
        prefix = "  " + "    " * depth + ("└── " if depth else "")
        command = clip((proc["cmd"] or "").replace("\n", " "), 96)
        lines.append(f"{prefix}{base(proc['exe'])} ({proc['pid']})  {command}")
        if depth == 0 and proc.get("parent_exe"):
            lines[-1] += f"   [parent: {base(proc['parent_exe'])} ({proc['parent_pid']}), not in this dataset]"
        for child in sorted(children.get(proc["guid"], []), key=lambda c: (c["first_ts"], c["guid"])):
            walk(child, depth + 1)

    for root in sorted(roots, key=lambda r: (r["first_ts"], r["guid"])):
        walk(root, 0)
    return "\n".join(lines) if lines else "  (no process creation events in this dataset)"


if __name__ == "__main__":
    sys.exit(main())
