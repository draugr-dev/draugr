#!/usr/bin/env bash
# Fail if anything world-readable describes the business around Draugr rather than the tool.
#
# This repository is the tool. Its docs explain what the engine does and where its edges are —
# and an edge is honestly described by the technical reason it exists ("this would need a service
# holding secrets", "this would need memory of previous runs"), never by who sells what is on the
# other side of it. A reader deciding whether to adopt an open-source scanner is not helped by
# knowing which capability is reserved, and a roadmap that names a commercial tier reads as a
# list of things deliberately withheld.
#
# **Naming a companion product is not the same thing, and is allowed.** A publisher that sends a
# run to Draugr Server is a capability of this tool: the reader gains an endpoint they can point at,
# including one they run themselves, and nothing is withheld from them by its existing. What stays
# out is the framing — tiers, what costs money, which capability sits behind a paywall. The test is
# whether a sentence tells a reader what they can do, or tells them what they cannot have.
#
# Terms about *third parties* are fine and sometimes necessary — Semgrep's commercial edition,
# VirusTotal's non-commercial terms — so the patterns below name our own framing rather than the
# words themselves.
set -uo pipefail

cd "$(dirname "$0")/.."

# Each pattern is a phrase that only appears when describing our own commercial side.
patterns=(
  'open-core'
  'monetiz'
  'enterprise (feature|connector|tier|control plane)'
  'commercial (layer|tier|control plane|offering)'
  '(the )?cloud backlog'
  'paid tier'
  'Yggdrasil'
)

found=0
for p in "${patterns[@]}"; do
  # Search tracked files only: build output and vendored trees are not ours to police.
  if hits=$(git grep -nIiE "$p" -- '*.md' '*.go' '*.yml' '*.yaml' '*.json' '*.sh' 2>/dev/null); then
    # scripts/check-public-scope.sh necessarily contains every pattern.
    hits=$(printf '%s\n' "$hits" | grep -v '^scripts/check-public-scope.sh:' || true)
    if [ -n "$hits" ]; then
      found=1
      printf '\n✗ %s\n%s\n' "$p" "$hits"
    fi
  fi
done

if [ "$found" -ne 0 ]; then
  cat >&2 <<'MSG'

This repository is world-readable and describes the tool, not the business around it.

Say why a capability is out of scope in technical terms — what it would need that a CLI
running in someone's pipeline should not have. That reason is true, useful, and survives
any change to how the project is funded.
MSG
  exit 1
fi
echo "check-public-scope: no commercial framing in tracked files ✓"
