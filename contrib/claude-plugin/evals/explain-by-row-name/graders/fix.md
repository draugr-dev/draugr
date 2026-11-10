---
type: llm
---

PASS if the reply does all three:

1. Identifies the rule as the one flagging the eval calls in services/api/src/index.js and
   services/web/src/index.js.
2. States that eval runs its argument as JavaScript code.
3. Gives a fix that removes the eval calls, or checks that no outside data reaches them.

FAIL if the reply says the rule could not be found or explained, or its only fix is to suppress or
accept the findings.
