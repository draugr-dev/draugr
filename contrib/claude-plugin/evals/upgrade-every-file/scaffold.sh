#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# A dependency scan of the api service, imported into sca, reports two lodash 4.17.15 advisories in
# package-lock.json and the same two again in a copy of lodash committed under public/vendor. The
# copies are counted once, under the lockfile's findings, and the one lodash upgrade names both
# files: bumping the lockfile leaves the committed copy as it was, so it has to be replaced too.
#
# No report.json, so the files have to come from the tools reading results.sarif.
mkdir -p reports services/api/public/vendor
printf '/*! lodash 4.17.15 */\n' >services/api/public/vendor/lodash.min.js
dep() { # rule message file fixed score
  printf '{"ruleId":"%s","level":"error","message":{"text":"%s"},' "$1" "$2"
  printf '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"}}}],' "$3"
  printf '"properties":{"security-severity":"%s","package":{"name":"lodash","version":"4.17.15","fixedVersion":"%s","ecosystem":"npm","purl":"pkg:npm/lodash@4.17.15"}}}' \
    "$5" "$4"
}
pollution="Prototype pollution in lodash zipObjectDeep"
injection="Command injection in lodash template"
{
  printf '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{'
  printf '"tool":{"driver":{"name":"dependency-fixture","version":"1.0.0"}},"results":['
  dep CVE-2020-8203 "$pollution" services/api/package-lock.json 4.17.19 7.4
  printf ','
  dep CVE-2021-23337 "$injection" services/api/package-lock.json 4.17.21 7.2
  printf ','
  dep CVE-2020-8203 "$pollution" services/api/public/vendor/lodash.min.js 4.17.19 7.4
  printf ','
  dep CVE-2021-23337 "$injection" services/api/public/vendor/lodash.min.js 4.17.21 7.2
  printf ']}]}\n'
} >reports/dependencies.sarif
git_ add reports services/api/public/vendor/lodash.min.js
git_ commit -q -m "Add the api service's dependency scan"
API_EXTRA="    imports:
      - control: sca
        file: reports/dependencies.sarif
"
descriptor
sarif_only .
