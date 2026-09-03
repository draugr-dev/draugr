#!/usr/bin/env bash
# Print the terminal output the docs quote, produced by a real scan of the demo sandbox.
#
# Six documents and a screenshot show `draugr scan .` output. They were transcribed by hand, which
# means they drift silently: nothing in CI reads them, and a rendering change or a new advisory
# leaves them subtly wrong in a way that costs a reader their trust in the rest of the page.
#
# The console golden test (pkg/report/golden_test.go) catches the *layout* changing. It cannot
# catch the numbers going stale, because the numbers come from real scanners against a real
# repository. This does: run it, read the output, paste what changed.
#
# Deliberately not run in CI. It clones a repo, downloads Trivy's database and takes a minute or
# two — and a job that rewrites documentation prose automatically would produce the kind of
# unreviewed churn the goldens exist to prevent.

set -euo pipefail

DEMO_REPO="${DEMO_REPO:-https://github.com/draugr-dev/draugr-demo}"
DRAUGR="${DRAUGR:-$(cd "$(dirname "$0")/.." && pwd)/bin/draugr}"

[ -x "$DRAUGR" ] || { echo "no draugr binary at $DRAUGR — run 'make build' first" >&2; exit 1; }

for tool in trivy gitleaks semgrep; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "warning: $tool is not on PATH — that control will report an error instead of findings" >&2
  }
done

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# The directory name matters: with no Saga present, `draugr scan .` names the release after the
# directory, and that name is in every example. Clone into draugr-demo so the output can be
# pasted verbatim — and so it matches the screenshot, which records the same sandbox.
echo "Cloning the demo sandbox…" >&2
git clone --quiet --depth 1 "$DEMO_REPO" "$workdir/draugr-demo"

# Warm Trivy's database off-camera so the first scan's progress bar doesn't land in the output
# anyone is about to copy.
echo "Warming the scanner databases (first run downloads Trivy's, which is slow)…" >&2
(cd "$workdir/draugr-demo" && "$DRAUGR" scan . >/dev/null 2>&1) || true

banner() { printf '\n\n===== %s =====\n\n' "$1"; }

banner "draugr scan .   → README.md, docs/concepts/verdict-and-gating.md, docs/contributing/*.md"
(cd "$workdir/draugr-demo" && NO_COLOR=1 "$DRAUGR" scan . 2>/dev/null) || true

banner "draugr scan . --format json --compact   → the machine-readable summary quoted in the docs"
(cd "$workdir/draugr-demo" && "$DRAUGR" scan . --format json --compact 2>/dev/null) || true

cat >&2 <<'EOF'


Done. The README and docs/concepts/verdict-and-gating.md quote abridged versions of the first
block — keep the abridgement, refresh the numbers and any column that moved.
EOF
