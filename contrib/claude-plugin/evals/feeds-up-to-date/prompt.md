---
description: Whether the data a scan ranks findings with is current comes from feeds_status, and a missing or stale feed is answered with the command it returns for the user to run
max_turns: 10
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep]
---

Is the vulnerability data Draugr uses on this machine up to date, or do I need to refresh it before I scan?
