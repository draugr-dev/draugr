#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
CONFIG='  exclude:
    - paths: ["services/web/src/index.js"]
      rules: ["draugr-fixture-eval"]
      reason: >-
        The web service passes only constants from its own templates to run(); no request data
        reaches it.
      acceptedBy: "Dana Reyes <dana@shop.example>"
' descriptor
report .
