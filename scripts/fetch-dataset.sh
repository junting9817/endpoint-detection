#!/usr/bin/env bash
# Download one recorded dataset into datasets/ and record where it came from.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/fetch-dataset.sh <dataset path or URL>

Download a recording from Security-Datasets (or another allowed repository) into datasets/, verify it is an archive,
extract the JSON next to it and print the dataset id to use with load-dataset.sh.

  <dataset path>   path inside Security-Datasets, e.g. atomic/windows/execution/host/empire_launcher_vbs.zip
  <URL>            full https URL on raw.githubusercontent.com or github.com

Nothing from the dataset is executed; only the archive is extracted.

Options:
  -h, --help   show this help

Environment:
  EP_DATA_DIR  where datasets are stored (default: /data/ep)
USAGE
}

die() { printf 'fetch-dataset: error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in -h | --help) usage; exit 0 ;; "") usage >&2; exit 2 ;; esac
[[ $# -eq 1 ]] || die "expected one dataset path or URL (see --help)"

DATA_DIR=${EP_DATA_DIR:-/data/ep}
BASE_URL=https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets
ALLOWED_HOSTS='^https://(raw\.githubusercontent\.com|github\.com)/'

for tool in curl 7z sha256sum; do command -v "$tool" >/dev/null || die "$tool is not installed"; done

arg=$1
if [[ "$arg" == http* ]]; then
  [[ "$arg" =~ $ALLOWED_HOSTS ]] || die "only raw.githubusercontent.com and github.com are allowed, got: $arg"
  url=$arg
else
  [[ "$arg" == *..* ]] && die "path must not contain '..'"
  url="$BASE_URL/${arg#/}"
fi
name=$(basename "$url")
[[ "$name" == *.zip ]] || die "expected a .zip dataset, got $name"
id=${name%.zip}
[[ "$id" =~ ^[A-Za-z0-9._-]+$ ]] || die "dataset name '$id' has characters this project does not allow"

mkdir -p "$DATA_DIR/datasets/$id"
dest="$DATA_DIR/datasets/$id/$name"
if [[ -f "$dest" ]]; then
  printf 'already downloaded: %s\n' "$dest"
else
  printf 'downloading %s\n' "$url"
  curl -sS -fL --max-time 900 -o "$dest.part" "$url" || die "download failed"
  mv "$dest.part" "$dest"
fi

magic=$(head -c 4 "$dest" | od -An -tx1 | tr -d ' \n')
[[ "$magic" == 504b0304* ]] || die "$name is not a zip archive (magic $magic); refusing to unpack it"

7z l "$dest" | tail -5
7z x -y -o"$DATA_DIR/datasets/$id" "$dest" '*.json' >/dev/null || die "could not extract the JSON from $name"
json=$(find "$DATA_DIR/datasets/$id" -maxdepth 2 -name '*.json' -newermt '-1 day' -o -maxdepth 2 -name '*.json' | head -1)
[[ -n "$json" ]] || die "no JSON file inside $name"

{
  printf 'dataset: %s\n' "$id"
  printf 'source_url: %s\n' "$url"
  printf 'archive: %s\n' "$(basename "$dest")"
  printf 'archive_sha256: %s\n' "$(sha256sum "$dest" | cut -d' ' -f1)"
  printf 'json: %s\n' "$(basename "$json")"
  printf 'json_sha256: %s\n' "$(sha256sum "$json" | cut -d' ' -f1)"
  printf 'json_lines: %s\n' "$(wc -l <"$json")"
} >"$DATA_DIR/datasets/$id/source.txt"
cat "$DATA_DIR/datasets/$id/source.txt"
printf '\nNext: scripts/new-case.sh <YYYY-MM-DD-technique> && scripts/load-dataset.sh %s <case>\n' "$id"
