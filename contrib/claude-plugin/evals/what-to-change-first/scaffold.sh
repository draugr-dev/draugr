#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# A third key, so the key action clears three findings and the eval action two. With two of each,
# "what clears the most" is a tie, and the order a reply gives would be a guess.
aws_key services/api/deploy/aws.staging.env
git_ add services/api/deploy/aws.staging.env
git_ commit -q -m "Add the staging credentials"
descriptor
report .
