#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# Two dependency scans of the api service's requirements.txt, imported into sca, each from a tool
# that spells the PyPI ecosystem its own way: one writes pip and Flask, as Trivy does, the other
# python and flask, as Grype does. Neither writes a package URL, so only the ecosystem names tie the
# two together. They report three different advisories against Flask 0.12.2, fixed in 0.12.3, 1.0
# and 2.2.5, and the fix list makes them one upgrade to 2.2.5 clearing all three. Kept apart by
# spelling, they would read as two upgrades of one package to two different versions.
#
# No report.json, so the upgrade has to come from the tools reading results.sarif.
mkdir -p reports
printf 'flask==0.12.2\n' >services/api/requirements.txt
dep() { # rule message name ecosystem fixed score
  printf '{"ruleId":"%s","level":"error","message":{"text":"%s"},' "$1" "$2"
  printf '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"services/api/requirements.txt"},"region":{"startLine":1}}}],'
  printf '"properties":{"security-severity":"%s","package":{"name":"%s","version":"0.12.2","fixedVersion":"%s","ecosystem":"%s"}}}' \
    "$6" "$3" "$5" "$4"
}
run() { # tool, then the results
  printf '{"tool":{"driver":{"name":"%s","version":"1.0.0"}},"results":[%s]}' "$1" "$2"
}
{
  printf '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":['
  run Trivy "$(dep CVE-2018-1000656 "Flask before 0.12.3 decodes JSON with an encoding an attacker chooses, which can exhaust memory" Flask pip 0.12.3 7.5),$(dep CVE-2023-30861 "Flask can send one client's session cookie to another through a caching proxy" Flask pip 2.2.5 7.5)"
  printf ','
  run Grype "$(dep CVE-2019-1010083 "Flask before 1.0 decodes JSON in a way an attacker can use to exhaust memory" flask python 1.0 7.5)"
  printf ']}\n'
} >reports/dependencies.sarif
git_ add reports services/api/requirements.txt
git_ commit -q -m "Add the api service's dependency scans"
API_EXTRA="    imports:
      - control: sca
        file: reports/dependencies.sarif
"
descriptor
sarif_only .
