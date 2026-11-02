---
type: llm
---

PASS if the reply does all three:

1. Names brotli's CVE, CVE-2026-111497, as the first thing to fix.
2. Says that CVE-2026-111497 is on CISA's Known Exploited Vulnerabilities (KEV) catalog, or that it
   is being exploited.
3. Puts the golang.org/x/net CVEs (CVE-2026-0001, CVE-2026-0002, CVE-2026-0003) after it.

FAIL if the reply puts a golang.org/x/net CVE first, or gives no reason that CVE-2026-111497 comes
first.

The imported SARIF carries no package data Draugr reads, so the fix list names each CVE rather than
an upgrade. A reply that names no fixed version is not failed for it.
