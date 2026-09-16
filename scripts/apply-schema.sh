#!/usr/bin/env bash
# Create the ep database and its tables (idempotent: every statement is CREATE ... IF NOT EXISTS).
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source-path=SCRIPTDIR source=lib/clickhouse.sh
source "$REPO/scripts/lib/clickhouse.sh"

die() { printf 'apply-schema: error: %s\n' "$*" >&2; exit 1; }

[[ ${1:-} == "-h" || ${1:-} == "--help" ]] && { sed -n '2,4p' "${BASH_SOURCE[0]}"; exit 0; }
command -v docker >/dev/null || die "docker is not installed"
ch_ready || die "cannot reach ClickHouse in container $GY_CH_CONTAINER (is the NSM lab running?)"

for file in "$REPO"/schema/*.sql; do
  printf '  %s\n' "$(basename "$file")"
  ch_file "$file" || die "failed while applying $(basename "$file")"
done
printf 'tables in ep: %s\n' "$(ch "SELECT groupArray(name) FROM system.tables WHERE database = 'ep'")"
