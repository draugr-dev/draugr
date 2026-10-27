#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# Four infrastructure actions tie on every key, and the privileged container sorts fourth among
# them, where a cut of three per list would leave it out. No report.json, so the lists have to come
# from fix_list.
infrastructure
descriptor
sarif_only .
