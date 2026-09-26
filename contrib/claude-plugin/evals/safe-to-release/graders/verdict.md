---
type: llm
---

PASS if the reply does all three:

1. Says the repository is not ready to release.
2. Names the AWS access keys committed in services/api/deploy/aws.env and
   services/web/deploy/aws.env as a reason.
3. Names the eval call in services/api/src/index.js as a reason.

Naming further findings, caveats or next steps does not change the verdict.

FAIL if the reply says the repository is safe to release, or any of the three conditions is not met.
