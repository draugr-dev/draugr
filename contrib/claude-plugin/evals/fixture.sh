#!/usr/bin/env bash
# Builds the workspace a case runs in, from the monorepo-paths sealed scenario: two services in one
# repository, each calling eval and each committing an AWS-shaped key, declared as two components
# scoped by paths. Sourced by each case's scaffold script, which runs in the empty workspace.
#
# The descriptor enables secrets and sast only. Both read files on disk and nothing else, so a scan
# is deterministic, needs no vulnerability database, and asks for no approval under the server's
# default --scan=effects.
set -euo pipefail

# Paths come from this file's own location. The descriptor names the rules by absolute path because
# Semgrep resolves a relative one against the component's path, not the repository root.
ECOSYSTEMS=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/../../../test/integration/testdata/ecosystems")
SCENARIO="$ECOSYSTEMS/monorepo-paths"
RULES="$ECOSYSTEMS/semgrep.yaml"

git_() { git -c user.name=eval -c user.email=eval@draugr.invalid -c commit.gpgsign=false "$@"; }

# aws_key writes a fresh AWS-shaped key, the shape gitleaks reports, into the file named.
aws_key() {
  mkdir -p "$(dirname "$1")"
  printf 'AWS_ACCESS_KEY_ID=AKIA%s\n' "$(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c16)" >"$1"
}

# repo copies the scenario's repository into the workspace and commits it, keys included.
repo() {
  cp -R "$SCENARIO/repo/." .
  find . -name '*.fixture' -exec sh -c 'mv "$1" "${1%.fixture}"' _ {} \;
  aws_key services/api/deploy/aws.env
  aws_key services/web/deploy/aws.env
  git_ init -q -b main
  git_ add -A
  git_ commit -q -m "Two services"
}

# descriptor writes draugr.saga.yaml for the workspace. The api service faces the internet and is
# critical; web is internal. Four variables change it, each a YAML fragment at the indent it lands
# at: WEB_PATHS replaces web's paths, CONTROLS adds controls, CONFIG adds keys under config, and
# API_EXTRA adds keys to the api component.
descriptor() {
  cat >draugr.saga.yaml <<YAML
project: shop
config:
${CONFIG:-}  controls:
${CONTROLS:-}    secrets:
      enabled: true
    sast:
      enabled: true
      semgrep:
        config: $RULES
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: .
        paths: [services/api]
${API_EXTRA:-}  - name: web
    exposure: internal
    criticality: supporting
    repositories:
      - url: .
        paths: [${WEB_PATHS:-services/web}]
YAML
  git_ add draugr.saga.yaml
  git_ commit -q -m "Describe the services to Draugr"
}

# report scans the committed workspace with the draugr on PATH and writes report.json and
# results.sarif into $1.
report() {
  draugr scan draugr.saga.yaml --no-gate --no-tips -o "$1" >/dev/null
}
