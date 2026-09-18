#!/usr/bin/env bash
# Whether a set of changed paths needs the integration suite run against it.
#
# Reads one path per line on stdin and prints `true` or `false`.
#
# The list below names what cannot reach the suite rather than what can, and the direction is the
# whole design. A list of relevant paths has to name every package the suite reaches into,
# including the ones that only produce what the tests read back; one it forgets turns a failure
# into a run that never happened, and nothing in the checks says so. A list of inert paths is wrong
# in the other direction: it costs several minutes of kind cluster and nothing else. So anything
# this file has never heard of runs the suite, and a new package is covered on the day it is added
# rather than on the day somebody remembers to list it.
#
# What earns a place here is a path that cannot be read by a Go test, a scanner or a build: prose,
# pictures, and the release notes. Not configuration, not fixtures, not workflows, and not the
# colocated documentation's neighbors.
set -euo pipefail

inert='^(docs/|changelog\.d/|LICENSE$|NOTICE$|\.github/ISSUE_TEMPLATE/|\.github/PULL_REQUEST_TEMPLATE)|\.(md|png|jpe?g|gif|svg|webp)$'

seen=false
while IFS= read -r path; do
	[ -n "$path" ] || continue
	seen=true
	if [[ ! $path =~ $inert ]]; then
		echo true
		exit 0
	fi
done

# An empty list is a diff that could not be read rather than a pull request that changed nothing,
# because a pull request that changed nothing does not exist. Answering "no" to a question that was
# never asked is how a suite stops running without anybody choosing that.
if [ "$seen" = false ]; then
	echo true
	exit 0
fi

echo false
