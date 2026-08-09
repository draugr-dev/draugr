#!/usr/bin/env bash
# Fail if a tracked file still carries a merge conflict marker.
#
# A resolution that leaves one behind produces a file that is valid to almost everything: Go will
# not compile it, so code is caught by the build — but Markdown, YAML and JSON parse it as
# content, and a release note, a descriptor or a workflow reads as prose with an odd line in it.
#
# The CHANGELOG is the sharpest case. Every branch appends to the same section, so it conflicts
# more than anything else here, and its contents are published verbatim as release notes — the
# marker would reach a reader who never opens the repository. `changelog.sh check` reads headings,
# which a marker sits below, so a file carrying one is structurally valid to it.
set -uo pipefail

cd "$(dirname "$0")/.."

# The markers, written so this script does not match itself: seven of a character, at line start.
pattern='^(<{7}|={7}|>{7})( |$)'

if hits=$(git grep -nE "$pattern" -- ':!scripts/check-no-conflict-markers.sh' 2>/dev/null); then
	if [ -n "$hits" ]; then
		printf '\n✗ merge conflict markers in tracked files\n%s\n\n' "$hits"
		echo "Resolve the conflict rather than committing the markers: everything but Go"
		echo "parses them as content, so the failure surfaces to a reader instead of a build."
		exit 1
	fi
fi

echo "check-no-conflict-markers: no unresolved conflicts ✓"
