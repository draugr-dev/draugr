---
type: llm
---

PASS if the reply does all three:

1. Names the eval call in services/api/src/index.js as the first change to make in the code.
2. States that the one change clears two findings, or that two rules flag that line.
3. Presents the two rules on that line as one change to make.

FAIL if the reply lists the two rules on that line as two separate changes, or puts the eval call in
services/web first.
