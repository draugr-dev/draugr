#!/usr/bin/env bash
# Two components import a dependency scan each. The change adds one finding to api's, CVE-2026-0103,
# which the scanner scored 7.5, high. It is on the KEV file the descriptor reads, so Draugr ranks it
# critical, and a gate on new findings set to critical fails on it. The findings already there are
# high and on no list, so nothing else the change touches reaches critical: a reply that judges the
# scanner's rating says the change passes.
#
# Imported SARIF and a local KEV file, so the scans run no scanner, fetch no feed and ask for no
# approval.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"

git_ init -q -b main
mkdir -p reports

cat >reports/kev.json <<'JSON'
{"title": "eval", "catalogVersion": "2026.11.05", "vulnerabilities": [{"cveID": "CVE-2026-0103"}]}
JSON

# sca writes a dependency scan holding one result per argument, each "id|score|text|uri".
sca() {
  local out=$1 sep=""
  shift
  {
    printf '{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{\n'
    printf '  "tool": {"driver": {"name": "Trivy", "version": "0.76.1", "rules": ['
    for r in "$@"; do
      IFS='|' read -r id score text uri <<<"$r"
      printf '%s\n    {"id": "%s", "shortDescription": {"text": "%s"}, "properties": {"security-severity": "%s"}}' "$sep" "$id" "$text" "$score"
      sep=","
    done
    printf '\n  ]}},\n  "results": ['
    sep=""
    for r in "$@"; do
      IFS='|' read -r id score text uri <<<"$r"
      printf '%s\n    {"ruleId": "%s", "level": "error", "message": {"text": "%s"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "%s"}, "region": {"startLine": 1}}}]}' "$sep" "$id" "$text" "$uri"
      sep=","
    done
    printf '\n  ]\n}]}\n'
  } >"$out"
}

API_BASE="CVE-2026-0101|7.5|openssl: timing side channel in RSA decryption|Dockerfile"
WORKER="CVE-2026-0102|7.8|golang.org/x/text: unbounded memory in language tag parsing|go.mod"
sca reports/api.sarif "$API_BASE"
sca reports/worker.sarif "$WORKER"

cat >draugr.saga.yaml <<'YAML'
project: shop
config:
  exploitability:
    kev: reports/kev.json
components:
  - name: api
    exposure: public
    criticality: critical
    imports:
      - control: sca
        file: reports/api.sarif
  - name: worker
    exposure: internal
    criticality: supporting
    imports:
      - control: sca
        file: reports/worker.sarif
YAML

git_ add -A
git_ commit -q -m "Import the dependency scans"
report base

sca reports/api.sarif "$API_BASE" "CVE-2026-0103|7.5|libxml2: use after free in the XML reader|Dockerfile"
git_ add reports/api.sarif
git_ commit -q -m "Upgrade the base image"
report head
