#!/usr/bin/env bash
# No cluster is reachable from the run. prompt.md points KUBECONFIG at a file that does not exist,
# so a run on a machine with a cluster configured never reads it either.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
