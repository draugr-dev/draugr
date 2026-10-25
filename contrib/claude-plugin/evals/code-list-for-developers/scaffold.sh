#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# A third key, so the credential action clears more findings than any code action. A reply that
# ranks every kind of work together then puts the keys first, which the question has ruled out.
aws_key services/api/deploy/aws.staging.env
git_ add services/api/deploy/aws.staging.env
git_ commit -q -m "Add the staging credentials"
descriptor
report .
