#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# The descriptor is committed without the exclusion first, and Dana Reyes adds the exclusion in a
# commit of her own. The git history of the exclusion's line names her, and the rest of the file
# names eval, so the answer has to come from that line's history rather than the file's.
descriptor
web_exclusion
GIT_AUTHOR_NAME="Dana Reyes" GIT_AUTHOR_EMAIL="dana@shop.example" descriptor
report .
