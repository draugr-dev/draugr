#!/usr/bin/env bash
# Two components import a scan each. api's is a secrets scan holding one generic API key, which the
# tool that wrote it scored 5.5, medium. The secrets control holds every finding at high whatever its
# scanner rated it, so Draugr ranks the key high and a gate set to high fails on it. worker's is a
# dependency scan holding one CVE scored 5.3, medium, which nothing moves. Both findings are medium
# by their scanners' ratings, so a reply that judges the rating says the scan passes.
#
# Imported SARIF, so the scan runs no scanner, fetches no feed and asks for no approval. report.json
# is removed, so the answer comes from results.sarif and the tools that read it.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"

git_ init -q -b main
mkdir -p reports

cat >reports/secrets.sarif <<'JSON'
{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
  "tool": {"driver": {"name": "Gitleaks", "version": "8.28.0", "rules": [
    {"id": "generic-api-key", "shortDescription": {"text": "Detected a Generic API Key"}, "properties": {"security-severity": "5.5"}}
  ]}},
  "results": [
    {"ruleId": "generic-api-key", "level": "warning", "message": {"text": "Detected a Generic API Key"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "deploy/app.env"}, "region": {"startLine": 3}}}]}
  ]
}]}
JSON

cat >reports/dependencies.sarif <<'JSON'
{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
  "tool": {"driver": {"name": "Trivy", "version": "0.76.1", "rules": [
    {"id": "CVE-2026-0105", "shortDescription": {"text": "golang.org/x/net: excessive memory use parsing HTML"}, "properties": {"security-severity": "5.3"}}
  ]}},
  "results": [
    {"ruleId": "CVE-2026-0105", "level": "warning", "message": {"text": "golang.org/x/net: excessive memory use parsing HTML"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.mod"}, "region": {"startLine": 1}}}]}
  ]
}]}
JSON

cat >draugr.saga.yaml <<'YAML'
project: shop
components:
  - name: api
    exposure: public
    criticality: critical
    imports:
      - control: secrets
        file: reports/secrets.sarif
  - name: worker
    exposure: internal
    criticality: supporting
    imports:
      - control: sca
        file: reports/dependencies.sarif
YAML

git_ add -A
git_ commit -q -m "Import the scans"
sarif_only out
