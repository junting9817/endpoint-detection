#!/usr/bin/env bash
# Lint every Sigma rule, run it over every loaded dataset, and score the result (docs/workflow.md step 8).
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/validate-rules.sh [options]

Check the rules in rules/sigma/ against the recordings in ep.win_events:

  1. Lint: required Sigma fields, a UUID id, an ATT&CK tag, named false positives, an entry in rules/README.md
  2. Convert each rule to ClickHouse SQL, refusing anything the backend cannot translate faithfully
  3. Run each rule over every loaded dataset
  4. Score: PASS/FAIL per expectation in rules/expected.yaml, false-positive candidates (a rule firing on a dataset
     where it is not expected or allowed), untested rules, and a rule x dataset coverage matrix

Writes rules/validation.txt and rules/validation.json.

Options:
  --strict      warnings (untested rules, lint warnings) fail too
  --no-write    print the report without updating rules/validation.*
  -h, --help    show this help

Exit status: 0 passed, 1 failed, 2 setup error.
USAGE
}

die() { printf 'validate-rules: error: %s\n' "$*" >&2; exit 2; }

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source-path=SCRIPTDIR source=lib/clickhouse.sh
source "$REPO/scripts/lib/clickhouse.sh"
extra=()
while (($#)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --strict | --no-write) extra+=("$1"); shift ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done

command -v python3 >/dev/null || die "python3 is not installed"
python3 -c 'import yaml' 2>/dev/null || die "PyYAML is missing (Debian: sudo apt-get install -y python3-yaml)"
command -v docker >/dev/null || die "docker is not installed"
ch_ready || die "cannot reach ClickHouse in container $GY_CH_CONTAINER (is the NSM lab running?)"

exec python3 "$REPO/scripts/lib/validate_rules.py" --repo "$REPO" "${extra[@]}"
