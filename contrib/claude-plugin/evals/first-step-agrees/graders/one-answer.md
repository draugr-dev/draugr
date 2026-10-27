---
type: llm
---

PASS if the reply does all three:

1. Names upgrading jquery from 1.8.3 to 3.5.0 as the first thing to do.
2. Names nothing else as the first thing to do: not the lodash upgrade, not CVE-2020-8203.
3. Says nothing about Draugr's tools, or its summary and its fix list, disagreeing about what comes
   first.

FAIL if the first thing the reply names is anything other than the jquery upgrade, or if the reply
reports a conflict between two answers Draugr gave.
