#!/usr/bin/env bash
# Compares Prowler's latest release on PyPI with tools.ProwlerTablesVersion, the release the scanner's
# tables of what each check reads were taken from, and keeps one issue open while a newer one is out.
#
#   scripts/prowler-tables.sh            open, update or close the issue (tool-bump's scheduled run)
#   scripts/prowler-tables.sh --dry-run  print what it would do, and write nothing
#
# Draugr runs the prowler on PATH and installs none, so no pin moves when Prowler releases, and
# without this nothing says the tables have fallen behind: every test passes over the old table.
set -euo pipefail

dry=false
[ "${1:-}" = "--dry-run" ] && dry=true

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tables=$(sed -n 's/^const ProwlerTablesVersion = "\([0-9][0-9.]*\)"$/\1/p' "$root/internal/tools/tools.go")
if [ -z "$tables" ]; then
  echo "prowler-tables: no ProwlerTablesVersion line in internal/tools/tools.go" >&2
  exit 1
fi
latest=$(curl -fsS --max-time 30 https://pypi.org/pypi/prowler/json | jq -r '.info.version')
if ! [[ "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "prowler-tables: PyPI gave '$latest' as Prowler's latest release" >&2
  exit 1
fi
newest=$(printf '%s\n%s\n' "$tables" "$latest" | sort -V | tail -1)
echo "prowler-tables: tables from $tables, latest release $latest"

label="prowler-tables"
run="${RUN_URL:-a local run}"
[ "$run" = "a local run" ] || run="[run]($run)"

if $dry; then
  if [ "$latest" != "$tables" ] && [ "$newest" = "$latest" ]; then
    echo "would open or update: Prowler $latest is out; regenerate the read tables"
  else
    echo "would close any open issue labeled $label"
  fi
  exit 0
fi

gh label create "$label" --description "Prowler released past the read tables" --color FBCA04 2>/dev/null || true
open=$(gh issue list --label "$label" --state open --limit 50 --json number --jq 'sort_by(.number) | .[].number')

if [ "$latest" != "$tables" ] && [ "$newest" = "$latest" ]; then
  title="Prowler $latest is out; regenerate the read tables"
  if [ -n "$open" ]; then
    first=$(head -1 <<<"$open")
    gh issue edit "$first" --title "$title"
    gh issue comment "$first" --body "Prowler $latest is the latest release as of $run. The tables are from $tables."
  else
    gh issue create --label "$label" --title "$title" --body "$(cat <<BODY
Prowler $latest is on PyPI, and the scanner's tables of what each check reads are from $tables (\`ProwlerTablesVersion\` in \`internal/tools/tools.go\`). Found by $run.

A check whose reads changed between the two releases can have its result discarded though it ran, or kept though a read it needs was denied.

To catch up, install Prowler $latest and:

- regenerate \`awsCheckReads\` in \`internal/scanners/prowler_aws_reads.go\` with \`scripts/prowler-check-reads.py\`, over the installed package and the framework's check list;
- for \`internal/scanners/prowler_gcp_reads.go\`, which has no generator, diff \`prowler/providers/gcp/\` between the two releases and read again each check whose clients or their calls changed, and any new service the framework now lists;
- set \`ProwlerTablesVersion\` to $latest, and move the \`prowlercloud/prowler\` image digest in \`.github/workflows/integration.yml\` to the $latest tag's, so the live cloud run checks the same release.

This issue closes itself when a scheduled run finds the tables at Prowler's latest release.
BODY
)"
  fi
else
  for n in $open; do
    gh issue comment "$n" --body "The tables are at Prowler's latest release, $latest, as of $run. Closing."
    gh issue close "$n"
  done
fi
