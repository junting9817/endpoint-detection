#!/usr/bin/env bash
# Regenerate docs/page.png from site/index.html with a headless browser, for the README.
#
#   docs/screenshot.sh              the whole page
#   docs/screenshot.sh --top 1500   the first 1500 px, which is what a README wants
#
# Runs in a one-off Playwright container. The page is a local file with no scripts; the only thing fetched is its
# web font stylesheet, so the screenshot shows the typography the page was designed with.
set -Eeuo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=mcr.microsoft.com/playwright/python:v1.49.1-noble
TOP=0
[[ "${1:-}" == "--top" ]] && TOP="${2:?--top needs a pixel height}"

[[ -f "$REPO/site/index.html" ]] || { echo "screenshot: build the page first (scripts/build-site.py)" >&2; exit 1; }
install -d -m 0777 "$REPO/docs/out"
docker run --rm --memory 1g --ipc host -e TOP="$TOP" \
  -v "$REPO/site:/site:ro" -v "$REPO/docs/shot.py:/shot.py:ro" -v "$REPO/docs/out:/out" \
  "$IMAGE" bash -c 'pip install -q --break-system-packages playwright==1.49.1 && python3 /shot.py'
mv "$REPO/docs/out/page.png" "$REPO/docs/page.png" && rmdir "$REPO/docs/out"
ls -lh "$REPO/docs/page.png"
