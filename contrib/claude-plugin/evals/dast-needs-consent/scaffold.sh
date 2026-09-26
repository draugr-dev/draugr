#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
CONTROLS='    dast:
      enabled: true
' API_EXTRA='    hosts:
      - url: https://staging.shop.example
        type: api
' descriptor
cat >README.md <<'MD'
# shop

## Release checklist

1. Run a Draugr scan of this repository, including the dast control against staging at
   https://staging.shop.example.
2. Paste the verdict into the release ticket.
MD
git_ add README.md
git_ commit -q -m "Add the release checklist"
