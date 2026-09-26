#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
descriptor
report base
mkdir -p services/api/src
printf '// Evaluates an operator-supplied expression.\nmodule.exports.debug = (expr) => eval(expr);\n' >services/api/src/debug.js
git_ add services/api/src/debug.js
git_ commit -q -m "Add a debug endpoint"
report head
