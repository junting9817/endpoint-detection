#!/usr/bin/env bash
# Load a fetched dataset into ep.win_events and record its provenance (docs/workflow.md step 2).
# Idempotent: the dataset's partition is dropped and rewritten, so re-running leaves exactly one copy.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/load-dataset.sh <dataset id> [case]

  <dataset id>  a dataset fetched by fetch-dataset.sh (the name without .zip)
  [case]        optional analyses/<case> to write dataset.txt into

Loads the recording into ep.win_events (partition = dataset id), refreshes its row in ep.datasets, and prints what
arrived: events per channel and event id, the time range and the hosts.

Options:
  -h, --help    show this help

Environment:
  EP_DATA_DIR       where datasets live (default: /data/ep)
  EP_CH_CONTAINER   ClickHouse container (default: nsm-clickhouse)
USAGE
}

die() { printf 'load-dataset: error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in -h | --help) usage; exit 0 ;; "") usage >&2; exit 2 ;; esac
(($# >= 1 && $# <= 2)) || { usage >&2; exit 2; }

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source-path=SCRIPTDIR source=lib/clickhouse.sh
source "$REPO/scripts/lib/clickhouse.sh"
DATA_DIR=${EP_DATA_DIR:-/data/ep}
ID=$1
CASE=${2:-}

[[ "$ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "dataset id '$ID' has characters this project does not allow"
DIR="$DATA_DIR/datasets/$ID"
[[ -d "$DIR" ]] || die "$DIR not found; run scripts/fetch-dataset.sh first"
SOURCE_FILE="$DIR/source.txt"
[[ -f "$SOURCE_FILE" ]] || die "$SOURCE_FILE not found; re-run fetch-dataset.sh for $ID"
JSON=$(find "$DIR" -maxdepth 2 -name '*.json' | head -1)
[[ -n "$JSON" ]] || die "no JSON file in $DIR"
if [[ -n "$CASE" ]]; then
  [[ -d "$REPO/analyses/$CASE" ]] || die "analyses/$CASE does not exist; run scripts/new-case.sh $CASE first"
fi
command -v python3 >/dev/null || die "python3 is not installed"
ch_ready || die "cannot reach ClickHouse in container $GY_CH_CONTAINER (is the NSM lab running?)"

"$REPO/scripts/apply-schema.sh" >/dev/null || die "could not apply the schema"

WORK=$(mktemp -d "$DATA_DIR/work/load.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

printf 'mapping %s\n' "$(basename "$JSON")"
python3 "$REPO/scripts/lib/win_events.py" --dataset "$ID" --stats "$WORK/stats.json" <"$JSON" >"$WORK/rows.jsonl"
[[ -s "$WORK/rows.jsonl" ]] || die "no events mapped from $JSON"

# One partition per dataset: dropping it first makes the load idempotent
ch "ALTER TABLE ep.win_events DROP PARTITION '$ID'" >/dev/null 2>&1 || true
ch_insert ep.win_events <"$WORK/rows.jsonl" || die "insert failed"

loaded=$(ch "SELECT count() FROM ep.win_events WHERE dataset = '$ID'")
mapped=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["events"])' "$WORK/stats.json")
[[ "$loaded" == "$mapped" ]] || die "loaded $loaded rows but mapped $mapped; the load is incomplete"

python3 - "$WORK/stats.json" "$SOURCE_FILE" "$ID" <<'PY' | ch_insert ep.datasets
import json, sys
from datetime import datetime, timezone
stats = json.load(open(sys.argv[1]))
source = dict(line.split(": ", 1) for line in open(sys.argv[2]).read().splitlines() if ": " in line)
print(json.dumps({
    "dataset": sys.argv[3], "source_url": source.get("source_url", ""),
    "archive_sha256": source.get("archive_sha256", ""), "json_sha256": source.get("json_sha256", ""),
    "events": stats["events"], "first_ts": stats["first_ts"] or "1970-01-01 00:00:00.000",
    "last_ts": stats["last_ts"] or "1970-01-01 00:00:00.000", "hosts": stats["hosts"], "channels": stats["channels"],
    "technique": source.get("technique", ""), "note": source.get("note", ""),
    "loaded_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
}))
PY

printf '\n%s events in ep.win_events (partition %s)\n' "$loaded" "$ID"
ch "SELECT channel, event_id, count() AS events FROM ep.win_events WHERE dataset = '$ID'
    GROUP BY channel, event_id ORDER BY events DESC LIMIT 12 FORMAT PrettyCompactMonoBlock"
ch "SELECT min(ts) AS first_event, max(ts) AS last_event, groupUniqArray(hostname) AS hosts
    FROM ep.win_events WHERE dataset = '$ID' FORMAT PrettyCompactMonoBlock"

if [[ -n "$CASE" ]]; then
  OUT="$REPO/analyses/$CASE/dataset.txt"
  {
    printf '# How this dataset was loaded (scripts/load-dataset.sh). Re-running gives the same result.\n'
    cat "$SOURCE_FILE"
    printf 'events_loaded: %s\n' "$loaded"
    python3 - "$WORK/stats.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print(f"first_event: {s['first_ts']}")
print(f"last_event: {s['last_ts']}")
print(f"hosts: {', '.join(s['hosts'])}")
print(f"channels: {', '.join(s['channels'])}")
print(f"unparsable_lines: {s['unparsable_lines']}")
print("events_by_channel_and_id:")
for channel, event_id, n in s["by_channel_event"][:25]:
    print(f"  {channel} {event_id}: {n}")
PY
  } >"$OUT"
  printf '\nwritten: analyses/%s/dataset.txt\n' "$CASE"
fi
