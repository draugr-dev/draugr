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
# a relative one resolves against the directory Draugr runs in, which the eval harness chooses.
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

# sarif_only scans like report, then removes report.json, so the actions and the next step can only
# come from the tools reading results.sarif, as for a SARIF file another pipeline produced.
sarif_only() {
  report "$1"
  rm -f "$1/report.json"
}

# shell_call commits a Python handler in the api service that passes request input to os.popen, the
# command injection the fixture's Semgrep rule draugr-fixture-os-popen reports.
shell_call() {
  mkdir -p services/api/app
  cat >services/api/app/ping.py <<'PY'
import os

from flask import request


def ping():
    return os.popen("ping -c 1 " + request.args["host"]).read()
PY
  git_ add services/api/app/ping.py
  git_ commit -q -m "Add a ping handler"
}

# dependencies stands in for a dependency scan another pipeline step ran: a SARIF 2.1.0 file for the
# api service's npm packages, which the descriptor imports into the sca control, and a copy of CISA's
# KEV catalog listing the one CVE in it known to be exploited. Call it before descriptor, which reads
# the CONFIG and API_EXTRA it sets.
#
# jquery 1.8.3 carries two medium findings, one of them on KEV, which raises it to critical. lodash
# 4.17.15 carries three, the worst of them high. Both are P1 in the api service, so the jquery upgrade
# leads the dependency list on the KEV finding alone, ahead of the upgrade that clears more.
dependencies() {
  mkdir -p reports
  dep() { # rule level score message package version fixed
    printf '{"ruleId":"%s","level":"%s","message":{"text":"%s"},' "$1" "$2" "$4"
    printf '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"services/api/package-lock.json"}}}],'
    printf '"properties":{"security-severity":"%s","package":{"name":"%s","version":"%s","fixedVersion":"%s","ecosystem":"npm","purl":"pkg:npm/%s@%s"}}}' \
      "$3" "$5" "$6" "$7" "$5" "$6"
  }
  {
    printf '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{'
    printf '"tool":{"driver":{"name":"dependency-fixture","version":"1.0.0"}},"results":['
    dep CVE-2020-11023 warning 6.1 "jQuery passes HTML containing option elements from untrusted sources to its DOM methods, which can execute it" jquery 1.8.3 3.5.0
    printf ','
    dep CVE-2020-11022 warning 6.1 "jQuery passes HTML from untrusted sources to its DOM methods, which can execute it" jquery 1.8.3 3.5.0
    printf ','
    dep CVE-2020-8203 error 7.4 "Prototype pollution in lodash zipObjectDeep" lodash 4.17.15 4.17.19
    printf ','
    dep CVE-2021-23337 error 7.2 "Command injection in lodash template" lodash 4.17.15 4.17.21
    printf ','
    dep CVE-2020-28500 warning 5.3 "Regular expression denial of service in lodash toNumber, trim and trimEnd" lodash 4.17.15 4.17.21
    printf ']}]}\n'
  } >reports/dependencies.sarif
  printf '{"vulnerabilities":[{"cveID":"CVE-2020-11023"}]}\n' >reports/kev.json
  git_ add reports
  git_ commit -q -m "Add the dependency scan and the KEV catalog"
  CONFIG="  exploitability:
    kev: reports/kev.json
"
  API_EXTRA="    imports:
      - control: sca
        file: reports/dependencies.sarif
"
}

# infrastructure stands in for a misconfiguration scan another pipeline step ran: a SARIF 2.1.0 file
# for the api service's Dockerfile and pod manifest, imported into the iac control. Call it before
# `descriptor`, which reads the `API_EXTRA` this extends.
#
# Four findings, all high and all P1 in the api service, each clearing one finding: they tie on every
# key an action ranks by, so their order among themselves comes from their file and line. The
# privileged container sorts fourth of four, past the console's cut of three.
infrastructure() {
  mkdir -p reports services/api/deploy
  printf 'FROM python:3.12-slim\nCOPY app /app\n' >services/api/Dockerfile
  cat >services/api/deploy/pod.yaml <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  containers:
    - name: api
      image: api:1.0
      securityContext:
        privileged: true
YAML
  mis() { # rule file line message
    printf '{"ruleId":"%s","level":"error","message":{"text":"%s"},' "$1" "$4"
    printf '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":%s}}}],' "$2" "$3"
    printf '"properties":{"security-severity":"8.0"}}'
  }
  {
    printf '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{'
    printf '"tool":{"driver":{"name":"misconfiguration-fixture","version":"1.0.0"}},"results":['
    mis DS-0002 services/api/Dockerfile 1 "Image user should not be 'root'"
    printf ','
    mis KSV-0118 services/api/deploy/pod.yaml 5 "Default security context configured"
    printf ','
    mis KSV-0014 services/api/deploy/pod.yaml 7 "Root file system is not read-only"
    printf ','
    mis KSV-0017 services/api/deploy/pod.yaml 7 "Privileged"
    printf ']}]}\n'
  } >reports/infrastructure.sarif
  git_ add reports services/api/Dockerfile services/api/deploy/pod.yaml
  git_ commit -q -m "Add the misconfiguration scan"
  API_EXTRA="${API_EXTRA:-    imports:
}      - control: iac
        file: reports/infrastructure.sarif
"
}
