#!/usr/bin/env bash
# Two components import the same Trivy SARIF. Every finding is critical, and so in one band, so the
# order inside the band decides the answer. golang.org/x/net clears three critical findings in each
# component, brotli-libs one. brotli's CVE is on the KEV file the descriptor reads, so its upgrade
# comes first in the band although it clears fewer findings: the one being exploited is the one to
# fix. KEV raises nothing here, because brotli's finding is already critical. A second listed CVE,
# rated high, is the case where KEV does raise the severity.
#
# Imported SARIF and a local KEV file, so the scan runs no scanner, fetches no feed and asks for no
# approval.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"

git_ init -q -b main

cat >kev.json <<'JSON'
{"title": "eval", "catalogVersion": "2026.10.30", "vulnerabilities": [{"cveID": "CVE-2026-111497"}, {"cveID": "CVE-2026-0009"}]}
JSON

cat >trivy.sarif <<'JSON'
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "Trivy", "version": "0.76.1", "rules": [
      {"id": "CVE-2026-111497", "shortDescription": {"text": "brotli: Out-of-Bounds Write in Google Brotli Decoder"}, "properties": {"security-severity": "9.8"}},
      {"id": "CVE-2026-0001", "shortDescription": {"text": "golang.org/x/net: HTTP/2 stream reset exhausts memory"}, "properties": {"security-severity": "9.1"}},
      {"id": "CVE-2026-0002", "shortDescription": {"text": "golang.org/x/net: HTML tokenizer reads past a buffer"}, "properties": {"security-severity": "9.1"}},
      {"id": "CVE-2026-0003", "shortDescription": {"text": "golang.org/x/net: proxy bypass through an IPv6 zone"}, "properties": {"security-severity": "9.1"}},
      {"id": "CVE-2026-0009", "shortDescription": {"text": "curl: cookie leak across redirects"}, "properties": {"security-severity": "7.5"}}
    ]}},
    "results": [
      {"ruleId": "CVE-2026-111497", "level": "error", "message": {"text": "Package: brotli-libs\nInstalled Version: 1.2.0-r1\nVulnerability CVE-2026-111497\nSeverity: CRITICAL\nFixed Version: 1.2.1-r0"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 1}}}]},
      {"ruleId": "CVE-2026-0001", "level": "error", "message": {"text": "Package: golang.org/x/net\nInstalled Version: v0.58.0\nVulnerability CVE-2026-0001\nSeverity: CRITICAL\nFixed Version: v0.60.0"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.mod"}, "region": {"startLine": 7}}}]},
      {"ruleId": "CVE-2026-0002", "level": "error", "message": {"text": "Package: golang.org/x/net\nInstalled Version: v0.58.0\nVulnerability CVE-2026-0002\nSeverity: CRITICAL\nFixed Version: v0.60.0"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.mod"}, "region": {"startLine": 7}}}]},
      {"ruleId": "CVE-2026-0003", "level": "error", "message": {"text": "Package: golang.org/x/net\nInstalled Version: v0.58.0\nVulnerability CVE-2026-0003\nSeverity: CRITICAL\nFixed Version: v0.60.0"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.mod"}, "region": {"startLine": 7}}}]},
      {"ruleId": "CVE-2026-0009", "level": "warning", "message": {"text": "Package: libcurl\nInstalled Version: 8.22.0-r0\nVulnerability CVE-2026-0009\nSeverity: HIGH\nFixed Version: 8.23.0-r0"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 2}}}]}
    ]
  }]
}
JSON

cat >draugr.saga.yaml <<'YAML'
project: shop
config:
  exploitability:
    kev: kev.json
components:
  - name: api
    exposure: public
    criticality: critical
    imports:
      - control: sca
        file: trivy.sarif
  - name: worker
    exposure: public
    criticality: critical
    imports:
      - control: sca
        file: trivy.sarif
YAML

git_ add -A
git_ commit -q -m "Import the image scan"
# Only the SARIF, so the order can only come from fix_list reading it.
sarif_only .
