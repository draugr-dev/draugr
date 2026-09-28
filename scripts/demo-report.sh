#!/usr/bin/env bash
# Render the HTML report of a real scan of the demo sandbox, the page draugr.dev serves at /demo/cli/report/.
#
#   scripts/demo-report.sh <out.html>
#
# The release workflow runs this against the binary it has just published and attaches the result
# to the release as draugr-demo-report.html. The site fetches that asset at build time, the same
# way it fetches the docs from the tag, so the page is always one release's real output and there
# is no copy in any repository to go stale or to be edited by hand.
#
# DRAUGR names the binary (default bin/draugr). DEMO_DIR is a checkout of the sandbox to scan; with
# none, DEMO_REPO is cloned. The scanners the demo's descriptor needs have to be installed already:
# `draugr tools install --saga draugr.saga.yaml` in a checkout of the demo.

set -euo pipefail

out="${1:?usage: scripts/demo-report.sh <out.html>}"
DEMO_REPO="${DEMO_REPO:-https://github.com/draugr-dev/draugr-demo}"
DRAUGR="${DRAUGR:-$(cd "$(dirname "$0")/.." && pwd)/bin/draugr}"

[ -x "$DRAUGR" ] || { echo "demo-report: no draugr binary at $DRAUGR, run 'make build' first" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "demo-report: jq is required to check the run" >&2; exit 1; }

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

demo="${DEMO_DIR:-$workdir/draugr-demo}"
[ -n "${DEMO_DIR:-}" ] || git clone --quiet --depth 1 "$DEMO_REPO" "$demo"

# The demo fails its gate by design, so a non-zero exit is the expected verdict and says nothing
# about whether the report was written. The two checks below decide that instead.
#
# --no-publish because the descriptor's `github` publisher would otherwise upload the demo's
# findings to the code scanning page of whichever repository this runs in.
(cd "$demo" && "$DRAUGR" scan draugr.saga.yaml --no-publish \
  -o "$workdir/out" --report html,json) || true

if [ ! -s "$workdir/out/report.html" ] || [ ! -s "$workdir/out/report.json" ]; then
  echo "demo-report: the scan wrote no report; its output is above" >&2
  exit 1
fi

# A control whose scanner could not run has found nothing, and a sample report showing one would
# present a broken environment as Draugr's output. Refused, so the site keeps the previous
# release's report rather than publishing this one.
broken=$(jq -r '.controls[] | select(.scanErrors) | "\(.name): \(.scanErrors | join("; "))"' "$workdir/out/report.json")
if [ -n "$broken" ]; then
  echo "demo-report: a control could not run, so this report is not published:" >&2
  printf '%s\n' "$broken" >&2
  exit 1
fi

mkdir -p "$(dirname "$out")"
cp "$workdir/out/report.html" "$out"
jq -r '"demo-report: \(.verdict) · \(.draugr.version) · \(.repositories[0].url)@\(.repositories[0].revision[0:7]) → '"$out"'"' \
  "$workdir/out/report.json"
