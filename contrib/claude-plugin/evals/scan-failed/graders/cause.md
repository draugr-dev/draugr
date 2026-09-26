---
type: llm
focus: trace
---

PASS if the agent does both:

1. Identifies that the web component's paths name services/wbe, a directory the repository does
   not have.
2. Either tells the user to change it to services/web, or edits draugr.saga.yaml to read
   services/web.

FAIL if the agent does not identify the mistyped path, or its fix, told or made, would not correct
it.
