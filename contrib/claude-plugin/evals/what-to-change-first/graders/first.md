---
type: llm
---

PASS if the reply does all three:

1. Names removing and rotating the committed AWS access keys as the first thing to change.
2. States that it clears two findings, one in each service.
3. Names fixing the eval calls as the other thing to change.

FAIL if the reply puts anything other than the AWS keys first, or gives no count of the findings
the first change clears.
