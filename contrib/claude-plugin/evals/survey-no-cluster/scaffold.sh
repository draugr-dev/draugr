#!/usr/bin/env bash
# No cluster is reachable from the run. A case can set only EVAL_* variables, so the README's
# command points KUBECONFIG at a file that does not exist, and a cluster this machine is configured
# for is never read.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
