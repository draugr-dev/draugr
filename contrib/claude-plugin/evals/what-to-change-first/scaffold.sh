#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# A third key, so the key action clears three findings, more than any other. Each service's eval
# call is an action of its own clearing one, so "what clears the most" has one answer.
aws_key services/api/deploy/aws.staging.env
git_ add services/api/deploy/aws.staging.env
git_ commit -q -m "Add the staging credentials"
descriptor
report .
