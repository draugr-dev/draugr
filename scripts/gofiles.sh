#!/usr/bin/env bash
# Prints the Go files this repository formats: every one outside a vendor/ directory.
#
# A vendor/ directory holds another project's code as that project published it. The sealed test
# fixtures vendor their dependencies so a scan can build them with no network, and reformatting
# those files would make the fixture differ from the module it claims to be.
set -euo pipefail
cd "$(dirname "$0")/.."
find . -name '*.go' -not -path '*/vendor/*' -not -path './.git/*' | sort
