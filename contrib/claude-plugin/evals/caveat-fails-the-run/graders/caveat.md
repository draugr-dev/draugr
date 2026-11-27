---
type: llm
---

PASS if the reply does all three:

1. Says no finding fails the run, because every finding was set aside.
2. Names the image the api component declares, python:3.12-slim, or the api component's images, as
   not checked because the images control is off.
3. Says the descriptor's `config.gate.failOnCaveats`, which lists `not-checked`, is what makes that
   fail the run.

FAIL if the reply attributes the failure to the AWS keys or the eval calls, or never names the
unchecked image.

Turning the images control on, taking the image out of the descriptor, and taking `not-checked` out
of `failOnCaveats` each make the run pass. A reply that suggests any of them, or none, is not failed
for it.
