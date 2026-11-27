---
type: llm
---

PASS if the reply does all three:

1. Recommends upgrading lodash from 4.17.15 to 4.17.21.
2. Names services/api/package-lock.json, alone or with services/api/package.json.
3. Names services/api/public/vendor/lodash.min.js as a committed copy of lodash that has to be
   replaced as well, because upgrading the package through npm leaves it as it was.

FAIL if the reply leaves out either file, or recommends a version below 4.17.21.
