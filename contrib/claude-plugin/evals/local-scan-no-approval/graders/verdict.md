---
type: llm
---

PASS if the reply does both:

1. Reports a failing verdict from a scan that ran.
2. Names the committed AWS keys among the findings.

FAIL if the reply says the scan could not run, says it needed approval, or reports no findings.
