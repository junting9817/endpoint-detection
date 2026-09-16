"""Convert a Sigma rule into a ClickHouse WHERE clause for ep.win_events.

Sigma is the portable format (the same rule converts to Splunk, Elastic or Sentinel with sigma-cli); this module is the
backend for the validation in this repository. It implements the subset the rules here use and **refuses anything it
cannot translate faithfully** — a silently mistranslated rule would pass validation while detecting nothing.

Supported: logsource category/service, named selection blocks (maps, or lists of maps), value lists (OR), the modifiers
contains / startswith / endswith / re / all, null values, wildcards * and ? inside values, and conditions built from
`and`, `or`, `not`, parentheses, `1 of <prefix>*`, `all of <prefix>*`, `1 of them`, `all of them`.
Not supported (raises SigmaError): aggregation expressions (`| count() > 3`), `near`, timeframes, base64 and utf16
modifiers, field references, and correlation rules.
"""
import re

FIELD_COLUMNS = {
    # Sigma field name -> ep.win_events column
    "image": "image", "originalfilename": "original_file_name", "commandline": "command_line",
    "currentdirectory": "current_directory", "parentimage": "parent_image",
    "parentcommandline": "parent_command_line", "user": "user", "integritylevel": "integrity_level",
    "logonid": "logon_id", "hashes": "hashes", "processid": "process_id", "processguid": "process_guid",
    "parentprocessguid": "parent_process_guid", "parentprocessid": "parent_process_id",
    "targetfilename": "target_filename", "targetobject": "target_object", "details": "details",
    "imageloaded": "image_loaded", "signature": "signature", "signaturestatus": "signature_status",
    "sourceimage": "source_image", "targetimage": "target_image", "grantedaccess": "granted_access",
    "calltrace": "call_trace", "destinationip": "destination_ip", "destinationport": "destination_port",
    "destinationhostname": "destination_hostname", "sourceip": "source_ip", "sourceport": "source_port",
    "protocol": "protocol", "initiated": "initiated", "logontype": "logon_type", "ipaddress": "ip_address",
    "scriptblocktext": "script_block", "computer": "hostname", "hostname": "hostname", "channel": "channel",
    "eventid": "event_id", "provider_name": "provider", "task": "task", "message": "message",
}
NUMERIC_COLUMNS = {"event_id", "process_id", "parent_process_id", "destination_port", "source_port", "task"}
# Sigma logsource -> the events that category means in this schema
CATEGORY_EVENTS = {
    "process_creation": [1, 4688], "network_connection": [3], "image_load": [7], "process_access": [10],
    "file_event": [11], "file_delete": [23, 26], "registry_add": [12], "registry_delete": [12],
    "registry_event": [12, 13, 14], "registry_set": [13], "registry_rename": [14], "create_remote_thread": [8],
    "pipe_created": [17, 18], "dns_query": [22], "wmi_event": [19, 20, 21], "process_tampering": [25],
    "ps_script": [4104], "ps_module": [4103], "ps_classic_start": [400], "driver_load": [6],
    "raw_access_thread": [9], "sysmon_error": [255], "create_stream_hash": [15],
}
SERVICE_CHANNELS = {
    "security": "Security", "system": "System", "application": "Application",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
}
UNSUPPORTED_MODIFIERS = {"base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "cidr", "expand",
                         "fieldref", "exists", "gt", "gte", "lt", "lte", "minute", "hour", "day"}
CONDITION_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*\*?|\b1 of\b|\ball of\b")


class SigmaError(Exception):
    """The rule is invalid, or uses something this backend will not translate."""


def quote(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def like_pattern(value: str, *, prefix: bool = False, suffix: bool = False, exact: bool = False) -> str:
    """Sigma value -> ILIKE pattern. Sigma wildcards are * and ?; SQL wildcards inside the value are escaped."""
    escaped = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    escaped = escaped.replace("*", "%").replace("?", "_")
    if exact:
        return escaped
    return ("" if prefix else "%") + escaped + ("" if suffix else "%")


def column_for(field: str) -> str:
    """Map a Sigma field to a column; unknown fields fall back to the `extra` map, which keeps every raw field."""
    name = field.split("|", 1)[0]
    column = FIELD_COLUMNS.get(name.lower())
    return column if column else f"extra[{quote(name)}]"


def condition_for(field: str, value) -> str:
    """One `field|modifiers: value` entry as SQL."""
    parts = field.split("|")
    name, modifiers = parts[0], [m.lower() for m in parts[1:]]
    for modifier in modifiers:
        if modifier in UNSUPPORTED_MODIFIERS:
            raise SigmaError(f"field '{field}': the '{modifier}' modifier is not supported by this backend")
    column = column_for(field)
    numeric = column in NUMERIC_COLUMNS

    if value is None:
        return f"({column} = '' OR {column} IS NULL)" if not numeric else f"{column} = 0"

    if isinstance(value, list):
        if not value:
            raise SigmaError(f"field '{field}': empty value list")
        joiner = " AND " if "all" in modifiers else " OR "
        return "(" + joiner.join(condition_for(field.replace("|all", ""), item) for item in value) + ")"

    if "re" in modifiers:
        return f"match({column}, {quote(value)})"
    if numeric:
        if not str(value).lstrip("-").isdigit():
            raise SigmaError(f"field '{field}': '{value}' is not a number but {column} is numeric")
        return f"{column} = {int(value)}"
    if "contains" in modifiers:
        return f"{column} ILIKE {quote(like_pattern(value))}"
    if "startswith" in modifiers:
        return f"{column} ILIKE {quote(like_pattern(value, prefix=True))}"
    if "endswith" in modifiers:
        return f"{column} ILIKE {quote(like_pattern(value, suffix=True))}"
    text = str(value)
    if "*" in text or "?" in text:
        return f"{column} ILIKE {quote(like_pattern(text))}"
    return f"{column} ILIKE {quote(like_pattern(text, exact=True))}"  # ILIKE without wildcards: case-insensitive equality


def block_sql(block, name: str) -> str:
    """A named selection: a map (AND over its entries) or a list of maps (OR over the maps)."""
    if isinstance(block, list):
        if not block:
            raise SigmaError(f"selection '{name}' is empty")
        return "(" + " OR ".join(block_sql(item, name) for item in block) + ")"
    if not isinstance(block, dict):
        raise SigmaError(f"selection '{name}' must be a map or a list of maps")
    if not block:
        raise SigmaError(f"selection '{name}' is empty")
    return "(" + " AND ".join(condition_for(field, value) for field, value in block.items()) + ")"


def logsource_sql(logsource: dict) -> str:
    """The logsource clause: category and service, as far as this schema can honour them."""
    if not isinstance(logsource, dict) or not logsource:
        raise SigmaError("logsource is missing")
    if logsource.get("product", "windows").lower() != "windows":
        raise SigmaError(f"logsource product '{logsource.get('product')}' is not supported (windows only)")
    clauses = []
    category = (logsource.get("category") or "").lower()
    if category:
        if category not in CATEGORY_EVENTS:
            raise SigmaError(f"logsource category '{category}' is not mapped to event ids in this schema")
        ids = ", ".join(str(i) for i in CATEGORY_EVENTS[category])
        clauses.append(f"event_id IN ({ids})")
    service = (logsource.get("service") or "").lower()
    if service:
        if service not in SERVICE_CHANNELS:
            raise SigmaError(f"logsource service '{service}' is not mapped to a channel in this schema")
        clauses.append(f"channel = {quote(SERVICE_CHANNELS[service])}")
    if not clauses:
        raise SigmaError("logsource needs a category or a service")
    return " AND ".join(clauses)


def condition_sql(condition: str, blocks: dict[str, str]) -> str:
    """Translate the `condition` line. Supports and/or/not, parentheses, '1 of x*', 'all of x*', '1 of them'."""
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaError("detection.condition is missing")
    text = " ".join(condition.split())
    if "|" in text:
        raise SigmaError("aggregation expressions (the '|' part of a condition) are not supported by this backend")
    if re.search(r"\bnear\b|\btimeframe\b", text, re.I):
        raise SigmaError("'near' and timeframes are not supported by this backend")

    def expand(match: re.Match) -> str:
        quantifier, target = match.group(1).lower(), match.group(2)
        if target == "them":
            names = list(blocks)
        else:
            prefix = target.rstrip("*")
            names = [n for n in blocks if n.startswith(prefix)]
        if not names:
            raise SigmaError(f"'{quantifier} of {target}' matches no selection")
        joiner = " or " if quantifier == "1" else " and "
        return "(" + joiner.join(names) + ")"

    text = re.sub(r"\b(1|all) of ([A-Za-z_][A-Za-z0-9_]*\*?|them)\b", expand, text)

    tokens = re.findall(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_]*", text)
    if " ".join(tokens).replace("( ", "(").replace(" )", ")") != text.replace("( ", "(").replace(" )", ")"):
        raise SigmaError(f"condition '{condition}' contains something this backend does not understand")
    out = []
    for token in tokens:
        lowered = token.lower()
        if lowered in ("and", "or", "not"):
            out.append(lowered.upper())
        elif token in ("(", ")"):
            out.append(token)
        elif token in blocks:
            out.append(blocks[token])
        else:
            raise SigmaError(f"condition refers to '{token}', which is not a selection in this rule")
    return " ".join(out)


def rule_to_sql(rule: dict) -> str:
    """The full WHERE clause for one Sigma rule (without the dataset filter)."""
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError("detection is missing")
    condition = detection.get("condition")
    blocks = {name: block_sql(block, name) for name, block in detection.items() if name != "condition"}
    if not blocks:
        raise SigmaError("detection has no selections")
    return f"({logsource_sql(rule.get('logsource', {}))}) AND ({condition_sql(condition, blocks)})"


def techniques(rule: dict) -> list[str]:
    """ATT&CK technique ids from the rule's tags (attack.t1059.001 -> T1059.001)."""
    found = []
    for tag in rule.get("tags") or []:
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).strip(), re.I)
        if match:
            found.append(match.group(1).upper())
    return sorted(set(found))
