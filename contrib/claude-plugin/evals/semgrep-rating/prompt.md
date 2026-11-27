---
description: A finding ranked below its SARIF level is explained by the rating report.json carries beside it, the rule's impact and likelihood
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep]
---

Our Semgrep rule for eval is severity ERROR. Why does report.json put the eval call in services/api at P2, below the AWS key at P1?
