---
type: llm
---

PASS if the reply names the eval call in services/api/src/debug.js as the one finding the change
introduced, and does not present the committed AWS keys or the eval calls in src/index.js as
introduced by the change.
FAIL if the reply misses debug.js, or counts any finding already present before the change as new.
