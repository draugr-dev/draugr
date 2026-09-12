#!/usr/bin/env bash
# Redraw the README's picture of a real scan.
#
# GitHub cannot show a terminal's colors, so the README carries a picture rather than a fenced
# block. A picture goes stale the way a transcription does and with less to warn anybody, so this
# regenerates it from the demo sandbox the same way `make examples` regenerates the quoted text.
#
# Narrowed to two controls on purpose. Unnarrowed, the demo's base image contributes four hundred
# findings that look alike, and a picture of those teaches nothing the counts above them do not
# already say.
#
# Deliberately not run in CI, for the reasons in examples.sh: it clones a repository, downloads
# Trivy's database, and rewrites a committed asset.
set -euo pipefail

DEMO_REPO="${DEMO_REPO:-https://github.com/draugr-dev/draugr-demo}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRAUGR="${DRAUGR:-$ROOT/bin/draugr}"
OUT="${OUT:-$ROOT/docs/assets/scan.svg}"
CONTROLS="${CONTROLS:-sca,secrets}"
TOP="${TOP:-7}"

[ -x "$DRAUGR" ] || { echo "no draugr binary at $DRAUGR, run 'make build' first" >&2; exit 1; }

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

echo "Cloning the demo sandbox…" >&2
git clone --quiet --depth 1 "$DEMO_REPO" "$workdir/draugr-demo"

# The descriptor reads the exploitability datasets from the cache and never fetches during a scan,
# so a picture that is meant to show what is being exploited has to fill the cache first.
echo "Fetching what is being exploited…" >&2
"$DRAUGR" feeds update >/dev/null

echo "Warming the scanner databases (first run downloads Trivy's, which is slow)…" >&2
(cd "$workdir/draugr-demo" && "$DRAUGR" scan draugr.saga.yaml --controls "$CONTROLS" >/dev/null 2>&1) || true

cmd="draugr scan draugr.saga.yaml --controls $CONTROLS"
# Under a pty, so the renderer colors its output the way it would for a person. COLORTERM is what
# a terminal uses to say it can show the project's own colors rather than the sixteen it has.
# The scan exits non-zero because the sandbox fails its own gate, which is the point of it, so the
# exit code is not this script's answer to anything.
( cd "$workdir/draugr-demo" &&
  COLORTERM=truecolor script -qec "$DRAUGR scan draugr.saga.yaml --controls $CONTROLS --top $TOP --no-publish" /dev/null || true
) 2>/dev/null | "$ROOT/scripts/screenshot.py" "$cmd" > "$OUT"

echo "wrote $OUT" >&2
