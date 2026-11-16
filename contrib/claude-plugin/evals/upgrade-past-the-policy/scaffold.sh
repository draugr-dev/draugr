#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# The api service's jquery 1.8.3 has two findings fixed in 3.5.0, a major step, and the descriptor
# allows minor upgrades only. No report.json, so the setting the step goes past has to come from
# fix_list reading results.sarif.
dependencies
CONFIG="${CONFIG}  fixes:
    upgrade: minor
"
descriptor
sarif_only .
