---
type: llm
---

PASS if the reply does all four:

1. Names the committed AWS access keys as the first thing to change.
2. States that it clears three findings.
3. Says the keys have to be rotated, revoked or replaced, as well as removed from the files.
4. Names fixing the eval call in services/api/src/index.js as the next thing to change, clearing one
   finding.

FAIL if the reply puts anything other than the AWS keys first, or gives no count of the findings
the first change clears.
