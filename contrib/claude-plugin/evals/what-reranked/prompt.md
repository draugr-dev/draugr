---
description: A change that only declares context moves findings' priority; a diff says so rather than "nothing changed"
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep]
---

base/ holds a Draugr scan from before my change and head/ one from after it. My change only edited draugr.saga.yaml. Did it change anything about the findings?
