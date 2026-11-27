#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# The project's own Semgrep rule for eval, written at severity ERROR, which Semgrep's SARIF level
# reads as high. Its metadata rates the impact high and the likelihood low, and Draugr ranks the
# finding by that rating, medium, keeping the level as Semgrep wrote it. report.json lists every
# finding, so the rating beside each eval call is in the file the question names.
mkdir -p rules
cat >rules/semgrep.yaml <<'YAML'
rules:
  - id: shop-eval
    languages: [javascript]
    severity: ERROR
    message: eval runs its argument as code
    pattern: eval(...)
    metadata:
      impact: HIGH
      likelihood: LOW
      confidence: HIGH
YAML
git_ add rules/semgrep.yaml
git_ commit -q -m "Add the project's Semgrep rule"
RULES=$(readlink -f rules/semgrep.yaml)
descriptor
report . --artifact-min-priority P4
