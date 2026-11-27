---
type: llm
---

PASS if the reply does all three:

1. Names Semgrep as the scanner that failed, in the sast control.
2. Says it failed for both the api and the web component, or for every component the descriptor
   declares.
3. Gives the reason as Semgrep rejecting the project's rules: rule validation failed, a
   RuleParseError, or the shop-eval rule in rules/semgrep.yaml having no pattern.

FAIL if the reply says Gitleaks or the secrets control failed, says Semgrep failed for one
component only, or says the sast control passed or found nothing to report.
