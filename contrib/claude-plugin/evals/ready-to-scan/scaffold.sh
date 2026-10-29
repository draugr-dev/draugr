#!/usr/bin/env bash
# The fixture's descriptor: sast with Semgrep selected by its block, secrets, and no config.sbom.
# gosec can also serve sast and syft is in the tool catalog; a scan of this descriptor runs neither.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
descriptor
