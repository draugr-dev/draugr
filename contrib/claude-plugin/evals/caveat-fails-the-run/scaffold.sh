#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# Every finding is set aside with a reason, so no finding fails the gate. The api service declares
# the image it runs, the images control is off, and config.gate.failOnCaveats lists not-checked, so
# the declared image nobody examined fails the run. report.json names it under failedCaveats.
CONFIG='  gate:
    failOnCaveats: [not-checked]
  exclude:
    - rules: ["aws-access-token"]
      reason: >-
        Both keys belong to a sandbox account that was closed; neither grants access to anything.
    - rules: ["draugr-fixture-eval"]
      reason: >-
        Each service passes only constants from its own templates to run(); no request data reaches
        it.
'
API_EXTRA='    images:
      - image: python:3.12-slim
'
descriptor
errored .
