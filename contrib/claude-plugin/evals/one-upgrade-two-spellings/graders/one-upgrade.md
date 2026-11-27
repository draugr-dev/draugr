---
type: llm
---

PASS if the reply does both:

1. Recommends one upgrade of Flask, from 0.12.2 to 2.2.5.
2. Says that upgrade clears all three Flask advisories, CVE-2018-1000656, CVE-2019-1010083 and
   CVE-2023-30861, or says it clears three findings.

FAIL if the reply presents Flask and flask as two packages or as two upgrades, recommends stopping
at 0.12.3 or 1.0, or leaves an advisory out of the upgrade.
