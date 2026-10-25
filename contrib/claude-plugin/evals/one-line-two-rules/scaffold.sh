#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# A second rule on the eval call each service makes, so one line is flagged twice and fix_list
# returns one action clearing both. The rules go in a directory of their own, outside the
# workspace, and the descriptor names it by its absolute path.
rules=$(mktemp -d)
cp "$RULES" "$rules/fixture.yaml"
cat >"$rules/caller-input.yaml" <<'YAML'
rules:
  - id: draugr-eval-caller-input
    languages: [javascript]
    severity: ERROR
    message: eval executes whatever string reaches it, so a caller who controls the string runs code
    pattern: eval(...)
YAML
RULES="$rules"
descriptor
report .
