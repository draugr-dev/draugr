#!/usr/bin/env bash
# Fail on a gosec suppression that one of the two gosec runs would not honor, or that names no rule
# or no reason.
#
# gosec runs twice: inside golangci-lint, and as the gosec scanner of Draugr's own `sast` control.
# `//nolint:gosec` is a golangci-lint directive, so it silences the first and not the second, and
# the line passes `make gate` while the self-scan reports it. `#nosec` silences both, and gosec
# carries the text after `--` into the report as the suppression's justification.
#
# A `#nosec` with no rule silences every gosec rule on the line, including one added after the
# line was reviewed.
set -uo pipefail

cd "$(dirname "$0")/.."

status=0

if hits=$(git grep -nE '//[[:space:]]*nolint:[^[:space:]]*\bgosec\b' -- '*.go'); then
	printf '\n✗ //nolint:gosec\n%s\n' "$hits"
	status=1
fi

# A directive is a comment that starts with #nosec; prose that mentions one is not.
if hits=$(git grep -nE '//[[:space:]]*#nosec' -- '*.go' |
	grep -vE '//[[:space:]]*#nosec G[0-9]+([ ,]G[0-9]+)* -- [^[:space:]]'); then
	printf '\n✗ #nosec without a rule and a reason\n%s\n' "$hits"
	status=1
fi

if [ "$status" -ne 0 ]; then
	echo
	echo "Write: // #nosec G304 -- <why this line is safe>"
	exit 1
fi

echo "check-gosec-suppressions: every suppression is #nosec with a rule and a reason ✓"
