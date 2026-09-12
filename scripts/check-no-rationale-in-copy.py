#!/usr/bin/env python3
"""Fail when a user-facing string argues for the design instead of describing the thing.

A note tells somebody what they are looking at. The reasoning behind the design is worth writing
down and belongs in the comment beside the code, where a contributor meets it; a reader who came to
find out what a number means did not ask for it, and reading the argument first makes the
description harder to find.

Three shapes, all of which have shipped in one file:

  No:  "These rules suppressed nothing. A rule that matches nothing claims a decision it is not
        making, and reads exactly like one that is working."
  Yes: "These rules suppressed nothing."

  No:  "One row per thing to do rather than per finding: eight advisories in one library are one
        upgrade. Always the whole run, so these agree with the counts at the top of the page."
  Yes: "One row per thing to do rather than per finding."

  No:  "Controls run in parallel, so these sum to more than the elapsed time, because the shares
        are of the total work rather than of the wall clock."
  Yes: name the column "Share of scanner time" and delete the sentence.

The third is the one worth learning from: a caption explaining why a number looks wrong is a
number that is labeled wrong.

Deliberately a phrase list rather than a grammar. The shapes that need catching are the ones with
no innocent reading in a report, and a rule broad enough to cover every argument would flag the
descriptions this exists to protect.
"""
import pathlib
import re
import sys

# Everything a reader meets. Comments in these files are exempt by construction: the patterns are
# searched inside quoted user-facing strings and template prose only.
SURFACES = [
    "pkg/report/html.go",
    "pkg/report/markdown.go",
    "pkg/report/console.go",
]

# Phrases that only appear when a string is arguing for the product rather than describing it.
TELLS = [
    r"teaches (them|a reader|somebody)",
    r"reads (exactly )?like",
    r"is not worth reading",
    r"claims a decision",
    r"so the decision is",
    r"which is what makes",
    r"rather than here",
    r"for the same reason",
    r"is the failure this",
    r"exists to prevent",
]

# The prose a reader meets: a note paragraph, a summary, or a cell of explanatory text. Comments
# and Go identifiers are not prose and are not read here.
PROSE = re.compile(
    r'<p class="note">(.*?)</p>|<span class="ctl-none">(.*?)</span>|<p class="empty"[^>]*>(.*?)</p>',
    re.S,
)


def offenders(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    for m in PROSE.finditer(text):
        prose = " ".join(g for g in m.groups() if g)
        flat = " ".join(re.sub(r"<[^>]+>|\{\{.*?\}\}", " ", prose).split())
        for tell in TELLS:
            if re.search(tell, flat, re.I):
                line = text[: m.start()].count("\n") + 1
                yield line, tell, flat[:120]


def main() -> int:
    found = []
    for name in SURFACES:
        path = pathlib.Path(name)
        if not path.exists():
            continue
        for line, tell, prose in offenders(path):
            found.append(f"  {name}:{line}  {tell}\n    {prose}")
    if not found:
        print("check-no-rationale-in-copy: copy describes rather than argues ✓")
        return 0
    print("check-no-rationale-in-copy: a user-facing string argues for the design.\n")
    print("\n".join(found))
    print(
        "\nSay what the thing is and stop. The reasoning belongs in the comment beside the code.\n"
        "Where a number needs a caption to stop it looking wrong, label the number instead."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
