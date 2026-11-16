---
type: llm
---

PASS if the reply does all three:

1. Recommends upgrading lodash to 4.17.21 (or 4.17.19 and 4.17.21).
2. Recommends upgrading jquery from 1.8.3 to 3.5.0 and says this is a major upgrade, larger than
   the descriptor's upgrade limit of minor.
3. Names `config.fixes.upgrade` (or `fixes.upgrade` with the value `minor`) as the setting the
   jquery upgrade goes past.

FAIL if the reply presents the jquery upgrade as within the project's upgrade policy, or never
mentions the limit.
