#!/usr/bin/env bash
# Scaffold an analysis case: analyses/<case>/report.md from TEMPLATE.md. Safe to re-run; existing files are kept.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/new-case.sh <case>

  <case>   YYYY-MM-DD-<technique>, e.g. 2026-09-20-empire-launcher-vbs
           (the date you analyse it; technique in lowercase letters, digits and hyphens)

Creates analyses/<case>/report.md (from TEMPLATE.md, with date and technique filled in) and the case folder.
USAGE
}

die() { printf 'new-case: error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in -h | --help) usage; exit 0 ;; "") usage >&2; exit 2 ;; esac
[[ $# -eq 1 ]] || die "expected exactly one argument (see --help)"

CASE=$1
[[ "$CASE" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})-([a-z0-9]+(-[a-z0-9]+)*)$ ]] ||
  die "case '$CASE' must look like YYYY-MM-DD-technique (lowercase letters, digits, single hyphens)"
DATE=${BASH_REMATCH[1]}
TECHNIQUE=${BASH_REMATCH[2]}
[[ "$(date -u -d "$DATE" +%F 2>/dev/null)" == "$DATE" ]] || die "'$DATE' is not a valid calendar date"

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
[[ -f TEMPLATE.md ]] || die "TEMPLATE.md not found"

mkdir -p "analyses/$CASE"
if [[ -e "analyses/$CASE/report.md" ]]; then
  printf 'kept     analyses/%s/report.md\n' "$CASE"
else
  sed -e "s/^date: YYYY-MM-DD$/date: $DATE/" \
    -e "s/^technique: <family or tool name, e.g. Empire launcher>$/technique: $TECHNIQUE/" \
    TEMPLATE.md >"analyses/$CASE/report.md.tmp"
  mv "analyses/$CASE/report.md.tmp" "analyses/$CASE/report.md"
  printf 'created  analyses/%s/report.md\n' "$CASE"
fi
printf '\nNext: scripts/fetch-dataset.sh <path>, then scripts/load-dataset.sh <dataset id> %s\n' "$CASE"
