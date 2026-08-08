#!/usr/bin/env bash
# Fail if anything world-readable explains a guard by recounting the defect that prompted it.
#
# Everything here is public: code comments, test rationale, workflow comments, config. A comment
# saying *why* a check exists is one of the most valuable things in this repository — and there
# are two ways to write it.
#
#   No:  "the licenses control shipped without its docs and the gap reached the published site."
#   Yes: "a plugin with no documentation still compiles and still passes its own tests; nothing
#         looks wrong until someone goes looking for the docs."
#
# The engineering value is entirely in the second half, and the second half survives the rewrite
# intact. The incident adds nothing a reader can act on, and a file of them reads as a defect log
# rather than as a design.
#
# The CHANGELOG is the exception, and only its `### Fixed` section: users need to know what
# changed in a release, described as the fix rather than as the blunder.
set -uo pipefail

cd "$(dirname "$0")/.."

# Phrases that only appear when narrating what went wrong here, rather than what could go wrong
# anywhere. Kept to the ones with no innocent reading — "used to" is deliberately absent, because
# it is also how the exclusion-expiry rules describe a *user's* finding that used to be accepted.
patterns=(
  'the hard way'
  'which is exactly what happened'
  'nobody noticed'
  'the first version of ours'
  '(we|it) regret'
  '(it|this) has (already )?happened'
  'has gone wrong (once|twice|before)'
  '(two|three) testers'
  'the original defect'
  'already failed once'
  'the defect (the|this|it)'
  'used to (silently|vanish|be silently)'
)

found=0
for p in "${patterns[@]}"; do
  # --untracked as well as tracked. A file that is not yet added is exactly where new prose
  # lands, so a check that skipped it would pass on the local run and fail in CI — silent on the
  # one commit that introduced the thing it looks for. Build output and vendored trees stay out
  # via the pathspecs. The CHANGELOG and the contributor guides are excluded — the first records
  # fixes for users by design, and the second two are where the rule itself is written down.
  if hits=$(git grep --untracked -nIiE "$p" -- '*.md' '*.go' '*.yml' '*.yaml' '*.json' '*.sh' '*.tape' \
    ':!CHANGELOG.md' ':!CLAUDE.md' ':!CONTRIBUTING.md' ':!scripts/check-no-defect-recounts.sh' 2>/dev/null); then
    if [ -n "$hits" ]; then
      found=1
      printf '\n✗ %s\n%s\n' "$p" "$hits"
    fi
  fi
done

if [ "$found" -ne 0 ]; then
  cat >&2 <<'MSG'

This repository is world-readable, and a guard should explain the risk it protects against
rather than the incident that prompted it.

Rewrite the comment as the failure mode, in the present tense, as something that could happen
to anyone reading it. That is the part a reader can act on, and it stays true after the
specific occasion is forgotten.

The CHANGELOG's `### Fixed` section is the exception: users need to know what changed.
MSG
  exit 1
fi
echo "check-no-defect-recounts: guards explain the risk, not the incident ✓"
