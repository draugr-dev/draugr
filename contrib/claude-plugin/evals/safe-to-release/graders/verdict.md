---
type: llm
---

PASS if the reply says the repository is not ready to release, and names as reasons both the AWS
access keys committed in services/api/deploy/aws.env and services/web/deploy/aws.env, and the eval
call in services/api/src/index.js.
FAIL if the reply says the repository is safe to release, or leaves out any of those three findings.
