---
type: llm
---

PASS if the reply does all three:

1. Attributes the difference to what the descriptor declares about each component.
2. States that api is declared public and critical, and web internal and supporting.
3. States that the finding is the same in both: the same rule, or the same severity.

FAIL if the reply attributes the difference to the code, the rule or a difference in severity, or
never mentions the components' declared exposure or criticality.
