#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# The project's Semgrep rules file holds a rule with no pattern, which Semgrep refuses, so the sast
# job of each component fails while Gitleaks runs and reports both keys. report.json lists semgrep
# among the scanners with each failed job and Semgrep's error.
mkdir -p rules
cat >rules/semgrep.yaml <<'YAML'
rules:
  - id: shop-eval
    languages: [javascript]
    severity: ERROR
    message: eval runs its argument as code
YAML
git_ add rules/semgrep.yaml
git_ commit -q -m "Add the project's Semgrep rule"
RULES=$(readlink -f rules/semgrep.yaml)
descriptor
errored .
