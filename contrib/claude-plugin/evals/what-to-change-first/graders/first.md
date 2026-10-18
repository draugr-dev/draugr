---
type: llm
---

PASS if the reply does all three:

1. Names the committed AWS access keys as the first thing to change.
2. States that it clears three findings.
3. Names fixing the eval calls as the next thing to change, clearing two findings.

FAIL if the reply puts anything other than the AWS keys first, or gives no count of the findings
the first change clears.
