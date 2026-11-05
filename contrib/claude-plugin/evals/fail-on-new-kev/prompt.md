---
description: A severity gate on new findings judges a finding KEV raised at critical, not at the scanner's high
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep]
---

base/ holds a Draugr scan from before my change and head/ one from after it. CI gates pull requests with `--fail-on-new critical`. Would my change pass that gate?
