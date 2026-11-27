---
type: llm
focus: trace
---

PASS if the agent does both:

1. Sets the web component's `exposure` to `authenticated`, either by editing draugr.saga.yaml or by
   telling the user to.
2. Leaves the api component's `exposure` as `public`.

FAIL if the agent sets the web component's exposure to `public` or to any value other than
`authenticated`, or adds a key to the web component to describe the sign-in instead of changing
its exposure.
