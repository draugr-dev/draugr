#!/usr/bin/env bash
# The feed cache is this machine's, under ~/.draugr/feeds, and a case can set only EVAL_* variables,
# so whether each feed is cached, current or stale depends on when the machine last fetched it. The
# grader reads the reply against what feeds_status returned in the trace rather than against a fixed
# answer.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
descriptor
