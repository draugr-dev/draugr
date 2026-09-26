---
type: llm
---

PASS if the reply attributes the difference to what the descriptor declares about each component:
api is declared public and critical, web internal and supporting, and the finding has the same
severity in both.
FAIL if the reply attributes the difference to the code, the rule or a difference in severity, or
never mentions the components' declared exposure or criticality.
