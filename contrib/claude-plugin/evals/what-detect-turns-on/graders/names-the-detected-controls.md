---
type: llm
---

PASS if the reply does all three:

1. Says the checks come from the files in the repository, because the descriptor sets
   config.detect (or detect: true).
2. Names sca, secrets and sast, or the dependency, credential and code checks they are.
3. Names iac, or the infrastructure-code check, for the Dockerfile, and gosec or govulncheck, or a
   Go-specific check, for go.mod.

FAIL if the reply says the descriptor enables no checks, or that nothing would be scanned.
