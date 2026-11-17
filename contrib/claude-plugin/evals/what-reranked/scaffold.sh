#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
descriptor
report base
# The change only declares api as internal and supporting: no finding arrives or leaves, and
# every one of api's findings ranks lower.
sed -e 's/exposure: public/exposure: internal/' -e 's/criticality: critical/criticality: supporting/' draugr.saga.yaml >draugr.saga.yaml.new
mv draugr.saga.yaml.new draugr.saga.yaml
git_ add draugr.saga.yaml
git_ commit -q -m "Declare the api as internal"
report head
