---
description: A severity gate judges a secret its scanner rated medium at high, the secrets control's floor
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep]
---

out/ holds the Draugr scan of this project. CI runs it with `--fail-on high`. Does this scan pass that gate?
