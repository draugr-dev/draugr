#!/usr/bin/env bash
# Whether a set of changed paths earns the changelog entry it carries.
#
# Reads one path per line on stdin. Prints nothing and exits 0 when the entry is warranted, or
# names the problem and exits 1 when it is not.
#
# # What this catches
#
# A changelog entry written for a change no user can observe. Everything else guarding this file
# guards its *mechanism*: one entry per change so branches cannot collide, no hand-editing so a
# section cannot land in the wrong place, released sections frozen so history is not rewritten.
# None of them asks the only question that decides whether an entry belongs, which is whether the
# change reaches anybody outside this repository.
#
# It got through. A fix to the text of an issue raised by our own CI workflow carried an entry all
# the way into published release notes, correct in form at every step.
#
# # Why the list names what cannot reach a user
#
# The opposite direction fails worse. A list of user-facing paths has to name every package whose
# output somebody reads, and one it forgets suppresses a real entry. That is a capability shipped
# and absent from the notes, which is invisible rather than noisy. This list is wrong in the other
# direction: it asks for a sentence of justification on a change that did not need one.
#
# So a path this file has never heard of earns its entry, and a new package is covered on the day
# it is added rather than the day somebody remembers.
set -euo pipefail

# Changes nobody outside this repository can observe: our own CI, our own tooling, our own tests,
# and the notes themselves. Contributing docs are here too; a contributor reads the repository,
# and the CHANGELOG speaks to somebody who installed a binary.
unreachable='^(\.github/|scripts/|changelog\.d/|docs/contributing/|Makefile$|\.golangci\.ya?ml$|\.gitignore$|\.goreleaser\.ya?ml$)|_test\.go$|^internal/ciguard/'

entry=false
reaching=()
while IFS= read -r path; do
	[ -n "$path" ] || continue
	if [[ $path =~ ^changelog\.d/.+\.md$ ]] && [[ $path != changelog.d/README.md ]]; then
		entry=true
		continue
	fi
	if [[ ! $path =~ $unreachable ]]; then
		reaching+=("$path")
	fi
done

# No entry is not this script's business. A change that should have one and has not is the other
# failure, and it is not mechanically decidable: plenty of user-facing commits are a second commit
# on a branch whose first one carried the entry.
[ "$entry" = true ] || exit 0

if [ ${#reaching[@]} -gt 0 ]; then
	exit 0
fi

cat >&2 <<'MSG'
changelog: an entry on a change no user can observe.

Everything changed here is this repository's own CI, tooling, tests or notes. The CHANGELOG
speaks to somebody who installed a binary, and what they can now do is unchanged.

Either drop the entry, or, if the change does reach a user in a way these paths do not show,
say so in the pull request and add the path to `unreachable` in this script with the reason.
MSG
exit 1
