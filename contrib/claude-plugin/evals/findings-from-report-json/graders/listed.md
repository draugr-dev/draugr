---
type: llm
---

PASS if the reply does both:

1. Lists an AWS access key at services/api/deploy/aws.env line 1.
2. Lists an AWS access key at services/web/deploy/aws.env line 1.

FAIL if the reply says the scan found no secrets, identifies the secrets by fingerprint alone with
no file, or names a file or line not in this list.
