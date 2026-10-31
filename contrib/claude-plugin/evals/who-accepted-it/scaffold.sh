#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# The exclusion names Dana Reyes in acceptedBy. No report.json, so the name, and what it is, have to
# come from summarize_report's accepted list.
web_exclusion
descriptor
sarif_only .
