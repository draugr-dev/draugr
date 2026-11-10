#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# The eval calls reported under a dotted id, the shape of a rule from Semgrep's registry. The row
# prints the rule's short name, eval-detected, on a line of its own under the instruction that titles
# it, and that short name is what the prompt asks about. The rules go in a directory of their own,
# outside the workspace, and the descriptor names it by its absolute path.
rules=$(mktemp -d)
cat >"$rules/registry-shaped.yaml" <<'YAML'
rules:
  - id: javascript.browser.security.eval-detected.eval-detected
    languages: [javascript]
    severity: WARNING
    message: Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content.
    pattern: eval(...)
YAML
RULES="$rules"
descriptor
report .
