#!/usr/bin/env python3
"""Turn recorded Windows events (newline-delimited JSON) into rows for ep.win_events.

Datasets from Security-Datasets are collected with nxlog, so every event carries the same envelope fields plus the
fields of its own event type. This module normalises the fields that matter across event types — a process creation
looks the same whether it came from Sysmon 1 or Security 4688 — and keeps everything else verbatim in `extra`.

Usage (as a filter):  win_events.py --dataset <id> < events.json > rows.jsonl
Standard library only. Reads local files; makes no network requests.
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

# nxlog envelope and collection artefacts: kept out of `extra` because they say nothing about the event itself
ENVELOPE = {
    "@timestamp", "@version", "host", "port", "tags", "EventTime", "EventReceivedTime", "ExecutionProcessID",
    "TimeCreated",
    "SourceModuleName", "SourceModuleType", "Severity", "SeverityValue", "Opcode", "OpcodeValue", "ThreadID",
    "Keywords", "Version", "ProviderGuid", "Category", "RuleName", "EventTypeOrignal", "ERROR_EVT_UNRESOLVED",
}
# Fields consumed by named columns; the rest of an event goes to `extra`
MAPPED = {
    "Channel", "EventID", "Hostname", "RecordNumber", "SourceName", "Task", "Message", "EventType",
    "User", "AccountName", "Domain", "SubjectUserName", "SubjectDomainName", "TargetUserName",
    "ProcessGuid", "SourceProcessGUID", "ProcessId", "NewProcessId", "SourceProcessId", "Image", "NewProcessName",
    "OriginalFileName", "CommandLine", "ProcessCommandLine", "CurrentDirectory", "IntegrityLevel", "LogonId",
    "SubjectLogonId", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentProcessName",
    "ParentCommandLine", "Protocol", "Initiated", "SourceIp", "SourcePort", "DestinationIp", "DestinationHostname",
    "DestinationPort", "IpPort", "TargetFilename", "TargetObject", "Details", "ImageLoaded", "Signature",
    "SignatureStatus", "SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "LogonType", "IpAddress",
    "ScriptBlockText",
}


def text(event: dict, *names: str) -> str:
    """First non-empty value among these field names."""
    for name in names:
        value = event.get(name)
        if value not in (None, "", "-"):
            return str(value)
    return ""


def number(event: dict, *names: str) -> int:
    """First numeric value among these field names; Security events write ids as hex strings such as '0x988'."""
    for name in names:
        value = event.get(name)
        if value in (None, "", "-"):
            continue
        try:
            if isinstance(value, str) and value.lower().startswith("0x"):
                return int(value, 16)
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


UTC_TIME_FIELDS = ("@timestamp", "UtcTime", "EventTime")
LOCAL_TIME_FIELD = "TimeCreated"  # present in some recordings, and not in UTC


def parse_time(raw: str):
    """'2020-09-04T20:09:55.953Z' or '2020-10-18 10:56:18.799' -> aware datetime, or None."""
    if not raw:
        return None
    try:
        moment = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def format_time(moment) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.") + f"{moment.microsecond // 1000:03d}"


def time_offset(events: list[dict]):
    """How far TimeCreated is from UTC in this recording, measured on the events that carry both fields.

    Some datasets write TimeCreated in the collecting host's own clock, so events that carry only that field would
    otherwise land hours away from the rest of the timeline. The offset is read from the data, never assumed.
    """
    deltas = []
    for event in events:
        local = parse_time(event.get(LOCAL_TIME_FIELD, ""))
        utc = parse_time(text(event, *UTC_TIME_FIELDS))
        if local and utc:
            deltas.append(round((utc - local).total_seconds()))
    if not deltas:
        return None, 0
    deltas.sort()
    return deltas[len(deltas) // 2], len(deltas)


def timestamp(event: dict, offset_seconds=None) -> tuple[str, str]:
    """(timestamp for ClickHouse, which field it came from)."""
    moment = parse_time(text(event, *UTC_TIME_FIELDS))
    if moment:
        return format_time(moment), "utc"
    local = parse_time(event.get(LOCAL_TIME_FIELD, ""))
    if local:
        if offset_seconds is None:
            return format_time(local), "local-unadjusted"
        return format_time(local + timedelta(seconds=offset_seconds)), "local-adjusted"
    return "1970-01-01 00:00:00.000", "missing"


def user_of(event: dict) -> str:
    """'DOMAIN\\user' from whichever fields this event type uses."""
    if event.get("User"):
        return str(event["User"])
    for domain_field, name_field in (("Domain", "AccountName"), ("SubjectDomainName", "SubjectUserName"),
                                     ("TargetDomainName", "TargetUserName")):
        name = text(event, name_field)
        if name:
            domain = text(event, domain_field)
            return f"{domain}\\{name}" if domain else name
    return ""


def to_row(event: dict, dataset: str, offset_seconds=None) -> tuple[dict, str]:
    """One ep.win_events row. Process creation is normalised across Sysmon 1 and Security 4688."""
    event_id = number(event, "EventID")
    ts, ts_source = timestamp(event, offset_seconds)
    is_4688 = event_id == 4688  # here ProcessId is the *creator*, NewProcessId the process that started
    row = {
        "dataset": dataset,
        "ts": ts,
        "record_id": number(event, "RecordNumber"),
        "hostname": text(event, "Hostname"),
        "channel": text(event, "Channel"),
        "provider": text(event, "SourceName"),
        "event_id": event_id,
        "task": number(event, "Task"),
        "user": user_of(event),

        "process_guid": text(event, "ProcessGuid", "SourceProcessGUID"),
        "process_id": number(event, "NewProcessId") if is_4688 else number(event, "ProcessId", "SourceProcessId"),
        "image": text(event, "Image", "NewProcessName", "SourceImage"),
        "original_file_name": text(event, "OriginalFileName"),
        "command_line": text(event, "CommandLine", "ProcessCommandLine"),
        "current_directory": text(event, "CurrentDirectory"),
        "integrity_level": text(event, "IntegrityLevel"),
        "logon_id": text(event, "LogonId", "SubjectLogonId"),
        "hashes": text(event, "Hashes"),
        "parent_process_guid": text(event, "ParentProcessGuid"),
        "parent_process_id": number(event, "ProcessId") if is_4688 else number(event, "ParentProcessId"),
        "parent_image": text(event, "ParentImage", "ParentProcessName"),
        "parent_command_line": text(event, "ParentCommandLine"),

        "protocol": text(event, "Protocol"),
        "initiated": text(event, "Initiated"),
        "source_ip": text(event, "SourceIp"),
        "source_port": number(event, "SourcePort"),
        "destination_ip": text(event, "DestinationIp"),
        "destination_hostname": text(event, "DestinationHostname"),
        "destination_port": number(event, "DestinationPort", "IpPort"),

        "target_filename": text(event, "TargetFilename"),
        "target_object": text(event, "TargetObject"),
        "details": text(event, "Details"),
        "image_loaded": text(event, "ImageLoaded"),
        "signature": text(event, "Signature"),
        "signature_status": text(event, "SignatureStatus"),
        "source_image": text(event, "SourceImage"),
        "target_image": text(event, "TargetImage"),
        "granted_access": text(event, "GrantedAccess"),
        "call_trace": text(event, "CallTrace"),

        "logon_type": text(event, "LogonType"),
        "ip_address": text(event, "IpAddress"),
        "script_block": text(event, "ScriptBlockText"),

        "message": text(event, "Message"),
        "extra": {k: str(v) for k, v in event.items() if k not in ENVELOPE and k not in MAPPED and v not in (None, "")},
    }
    return row, ts_source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", required=True, help="dataset id, used as the ClickHouse partition")
    parser.add_argument("--stats", help="write a JSON summary (counts, time range, hosts, channels) to this file")
    args = parser.parse_args()

    counts: dict[tuple, int] = {}
    hosts: set[str] = set()
    channels: set[str] = set()
    sources: dict[str, int] = {}
    first = last = ""
    total = bad = 0
    out = sys.stdout

    # Datasets are recordings of minutes, so reading them into memory is fine — and the TimeCreated offset can only be
    # measured by looking at the whole file first.
    events = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(event, dict):
            events.append(event)
        else:
            bad += 1
    offset, measured_on = time_offset(events)

    for event in events:
        row, ts_source = to_row(event, args.dataset, offset)
        out.write(json.dumps(row, ensure_ascii=False) + "\n")
        total += 1
        sources[ts_source] = sources.get(ts_source, 0) + 1
        counts[(row["channel"], row["event_id"])] = counts.get((row["channel"], row["event_id"]), 0) + 1
        if row["hostname"]:
            hosts.add(row["hostname"])
        if row["channel"]:
            channels.add(row["channel"])
        if row["ts"] != "1970-01-01 00:00:00.000":
            first = row["ts"] if not first or row["ts"] < first else first
            last = row["ts"] if not last or row["ts"] > last else last

    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as handle:
            json.dump({"events": total, "unparsable_lines": bad, "first_ts": first, "last_ts": last,
                       "timestamp_sources": dict(sorted(sources.items())),
                       "timecreated_offset_seconds": offset, "offset_measured_on_events": measured_on,
                       "hosts": sorted(hosts), "channels": sorted(channels),
                       "by_channel_event": sorted(([c, e, n] for (c, e), n in counts.items()), key=lambda r: -r[2])},
                      handle, indent=1)
    note = ""
    if sources.get("local-adjusted"):
        note = (f"; {sources['local-adjusted']} events had only {LOCAL_TIME_FIELD}, shifted by {offset} s "
                f"(offset measured on {measured_on} events carrying both fields)")
    elif sources.get("local-unadjusted"):
        note = f"; {sources['local-unadjusted']} events used {LOCAL_TIME_FIELD} as-is (no event carried both fields)"
    if sources.get("missing"):
        note += f"; {sources['missing']} events had no usable timestamp"
    print(f"{total} events mapped, {bad} unparsable lines{note}", file=sys.stderr)
    return 1 if total == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
