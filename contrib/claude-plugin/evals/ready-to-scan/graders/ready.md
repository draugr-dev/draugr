---
type: llm
---

PASS if the reply does both:

1. Says the machine is ready to scan this repository, or that nothing has to be installed first.
2. Names gitleaks or semgrep among the scanners the scan uses, or says the scanners it needs are
   installed.

FAIL if the reply tells the user to install any tool, names gosec or syft as required or missing,
or says the machine is not ready.
