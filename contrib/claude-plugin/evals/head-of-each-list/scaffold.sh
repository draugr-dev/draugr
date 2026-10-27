#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# A command injection in the api service heads the code list, tied with the api service's eval, and
# the jquery upgrade, whose finding is on KEV, heads the dependency list ahead of the lodash upgrade
# that clears more. No report.json, so the lists and the reasons have to come from fix_list.
shell_call
dependencies
descriptor
sarif_only .
