---
type: llm
---

PASS if the reply does all four:

1. Names the committed GitHub personal access tokens as the first thing to change.
2. States that it clears fourteen findings.
3. Says the tokens have to be rotated, revoked or replaced, as well as removed from the files.
4. Names the committed private keys as the next thing to change, clearing eleven findings.

FAIL if the reply puts anything other than the GitHub tokens first, or gives no count of the
findings the first change clears.
