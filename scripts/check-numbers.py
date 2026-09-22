#!/usr/bin/env python3
"""Refuse a count of Draugr's own capabilities on the front door.

The README said "Eleven controls" over a table of twelve. It was true when written, and the twelfth
control arrived without anybody opening the README. Nothing caught it, twice: once when the count
went stale, and once when it was corrected to "Twelve" rather than removed.

Counting what is already on the screen serves nobody. The table under that sentence is the count,
it cannot go stale, and a reader gets the same answer from it. A number earns its place when it
accounts for something **absent**: `1 of 2 images checked, 1 unsigned` says what was not reached,
and `10 actions clear 497 findings` says what a run did. Neither can be read off the page instead.

# Why only the front door

Tried against every document here, this fires on eight legitimate sentences for each real one.
"Two scanners fetch on every invocation" and "a flaw two scanners both found" are reasoning about a
pair, not a census, and no pattern separates them from an inventory without reading the meaning. A
check that cries wolf is worse than none, because the next person adds a skip rather than a fix.

So it covers the pages somebody reads before they have decided anything, where a count of the
product's own size is always a claim and never a measurement. Everywhere else the rule is written
down in CLAUDE.md and applied by whoever is writing.
"""
import re
import sys
from pathlib import Path

# The front doors. A count here is a claim about how big Draugr is.
FRONT = ["README.md"]

WORD_NUMBERS = (
    r"one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
    r"sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty"
)
COUNT = rf"(?:\d[\d,]*|{WORD_NUMBERS})"
# The things this project enumerates and then adds to.
CAPABILITY = r"controls?|scanners?|surveyors?|checks?|kinds?\s+of\s+check|publishers?|formats?"
INVENTORY = re.compile(rf"\b({COUNT})\s+({CAPABILITY})\b", re.I)

FENCE = re.compile(r"^\s*(?:```|~~~)")
# Alt text describes one screenshot, and the count in it is what that picture shows. It is
# regenerated with the picture by `make screenshot`, so it is a measurement rather than a claim.
ALT = re.compile(r'\balt="[^"]*"', re.S)


def offenders(path: Path) -> list[tuple[int, str]]:
    out, in_fence = [], False
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for m in INVENTORY.finditer(ALT.sub("", line)):
            out.append((n, m.group(0).strip()))
    return out


def main() -> int:
    found = []
    for name in FRONT:
        path = Path(name)
        if not path.is_file():
            continue
        for line_no, text in offenders(path):
            found.append((path, line_no, text))
    if not found:
        print("check-numbers: the front door counts nothing that can go stale ✓")
        return 0
    print("check-numbers: a count of what Draugr has, on a page that will not be reread.\n")
    for path, line_no, text in found:
        print(f"  {path}:{line_no}  {text!r}")
    print(
        "\nThe list under it is the count, and it cannot go stale. Say 'each control' rather than\n"
        "'twelve controls'. A number earns its place by accounting for something absent, the way\n"
        "'1 of 2 images checked, 1 unsigned' does."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
