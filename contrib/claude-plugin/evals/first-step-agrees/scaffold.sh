#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# summarize_report lists the lodash finding first among the findings, on its score, while the jquery
# upgrade clearing a finding on KEV leads fix_list. The step summarize_report names has to be the
# jquery upgrade. No report.json, so it has to come from the tools.
shell_call
dependencies
descriptor
sarif_only .
