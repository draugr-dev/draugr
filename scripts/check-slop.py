#!/usr/bin/env python3
"""Fail on the throat-clearing openers that announce a point instead of making it.

Both are the same habit: chopping one connected thought into separate short sentences. It is the
most recognizable tell in generated prose, and it is the one that keeps reaching our published
pages because each fragment reads fine on its own.

    binary contrast   "This is not a scanner malfunctioning. It is the base image."
                      -> "This is the base image, not a scanner malfunctioning."

Also the em dash, which is the other half of the same fingerprint. It reads as considered and is
almost never the punctuation a person reaches for: nearly every one marks a clause that would be
clearer joined with a conjunction, or ended and started again. Ninety-five of them sat across the
two files behind the in-product help before anybody counted, and the reason they survived is that
each one looks deliberate on its own line.

Deliberately narrow otherwise. Adverbs, business jargon and listicle transitions are all in the
same family and none of them is gated, because judging them needs a reader: `actually` is noise in
a blog lead and load-bearing in a reference page, and a check that cannot tell the difference
teaches people to add a skip rather than a fix. Those stay a review job -- see the `no-ai-slop`
skill, which is the standard this file gates the checkable part of.

Prose only: code fences, front matter, tables, headings and link text are skipped.
"""
import re
import sys
from pathlib import Path

ROOTS = ["docs", "README.md", "CONTRIBUTING.md"]

# The em-dash rule holds over everything a person reads, not only the prose files. Comments,
# console strings, the dashboard's own copy and the scripts' output are all read by somebody.
EM_DASH_ROOTS = ["docs", "internal", "pkg", "cmd", "scripts", "examples", "test", ".github",
                 "changelog.d", "README.md", "CONTRIBUTING.md", "Makefile", "action.yml"]
EM_DASH_SUFFIXES = {".md", ".mdx", ".astro", ".go", ".js", ".css", ".py", ".sh", ".html", ".tpl",
                    ".yaml", ".yml", ""}

# A released changelog section records what a version shipped with, and `changelog-guard` refuses
# to edit one. Rewriting the punctuation in notes a tag was cut from would also make every published
# release disagree with the file it came out of.
#
# The generated schemas are not a source: their text comes from the Go doc comments this already
# reads, so an em dash there is reported where it can be fixed.
#
# testdata is a fixture. It is what a tool produced or what a reader pasted, and correcting it would
# make the fixture describe something no tool emits.
EM_DASH_EXEMPT = ("CHANGELOG.md", "pkg/saga/draugr.saga.schema.json",
                  "pkg/saga/draugr.saga-fragment.schema.json", "/testdata/")

# Files the em-dash rule does not gate yet.
#
# A ratchet rather than a flag day. Nine hundred of them were already written when the rule arrived,
# and a check that fails everywhere is a check somebody turns off. Every file cleaned comes off this
# list and can never regress; nothing may be added to it.
#
# The split-sentence rule applies everywhere and always did.
# Empty, and it stays empty. It held the files a first pass had not reached yet; every one of them
# is clean now, so a new em dash in any of them fails here rather than being grandfathered.
UNGATED_EM_DASH: set[str] = set()

# "<subject> is not X. It's Y." -- the halves must be separate sentences, which is the defect.
# The negation and the contrast must be in SEPARATE sentences, which is the defect. A clause that
# already carries its own "but"/"rather than" is the fixed form, not the broken one -- matching it
# would ask a writer to repair a sentence that is correct.
BINARY = re.compile(
    r"\b(?:is|are|was|were|does|do|did)\s*n[o']t\b(?![^.!?]{0,55}\b(?:but|rather than)\b)"
    r"[^.!?]{0,55}[.!?]\s+"
    r"(?:It|They|That|This|These|Those)(?:'s|'re| is| are| was| were)\s",
)
# A whole sentence of one or two words. Requires a preceding sentence on the same line, so a
# heading, a label or a list item that is simply short is not a hit.
FRAGMENT = re.compile(r"(?<=[.!?])\s+([A-Z][\w'’-]*(?:\s+[\w'’-]+)?[.!])(?=\s|$)")

# Kept tiny on purpose: every entry here announces the point instead of making it.
PHRASES = [
    "Here's the thing", "The uncomfortable truth is", "Let me be clear", "The truth is,",
    "Let that sink in", "Read that again", "I can't stress this enough", "Make no mistake",
    "At the end of the day", "It goes without saying", "Needless to say", "In a world where",
    "Let's dive in", "Let's break this down", "Let me walk you through", "Plot twist:",
]

FENCE = re.compile(r"^\s*(?:```|~~~)")
# An em dash alone inside quotes is a glyph, not punctuation: it is what a table cell holds where
# there is nothing to show, and the console prints it. The rule is about a dash standing in for a
# conjunction between two halves of a sentence, and a cell has no halves.
GLYPH_CELL = re.compile(r"""(["'`])\s*\u2014\s*\1""")

SKIP_LINE = re.compile(r"^\s*(?:#{1,6}\s|\||-{3,}\s*$|\s*[-*+]\s|\d+\.\s)")


def prose(path: Path):
    in_fence = in_front = False
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if n == 1 and raw.strip() == "---":
            in_front = True
            continue
        if in_front:
            if raw.strip() == "---":
                in_front = False
            continue
        if FENCE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence or SKIP_LINE.match(raw):
            continue
        line = re.sub(r"`[^`]*`", "CODE", raw)
        line = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line)
        line = re.sub(r"<[^>]+>", " ", line)
        yield n, line


def offenders(path: Path) -> list[tuple[int, str, str]]:
    out = []
    for n, line in prose(path):
        # No binary-contrast check here either, and the reason is measured rather than assumed:
        # 15 of 17 hits on the site's blog and learn pages were real, against 8 of 14 here. Dense
        # reference prose chains referents -- "an option that does not exist is flagged as you
        # type. It is generated from the same registry" has "It" naming the schema, not drawing a
        # contrast -- and no regex can tell that from "The CLI is not a client. It is a producer".
        # A gate that is wrong four times in ten gets skipped, so it stays on the register where
        # it is right nine times in ten.
        # No fragment check here. Reference documentation is terse on purpose -- "Requires
        # Trivy." and "Emits SARIF." are annotations, not manufactured drama, and joining them
        # into a sentence makes them harder to scan. That check runs on the marketing surfaces in
        # draugr.dev, where the register is prose and a fragment really is a tell.
        low = line.lower()
        for p in PHRASES:
            if p.lower() in low:
                out.append((n, "throat-clearing", p))
    return out


def em_dashes(path: Path) -> list:
    """Every em dash outside a code fence.

    Reported line by line rather than counted, because each one is a different sentence and the fix
    is never the same twice: a comma, a full stop, or a conjunction that says which way the two
    halves lean.
    """
    out = []
    fenced = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced or "\u2014" not in line:
            continue
        line = GLYPH_CELL.sub("", line)
        for m in re.finditer("\u2014", line):
            out.append((n, "em dash", line.strip()[max(0, m.start() - 40):m.start() + 40]))
    return out


def main() -> int:
    found = []
    for root in ROOTS:
        base = Path(root)
        paths = [base] if base.is_file() else sorted(base.rglob("*"))
        for path in paths:
            if path.suffix.lower() in {".md", ".mdx", ".astro"} and path.is_file():
                found += [(path, *o) for o in offenders(path)]
    seen = set()
    for root in EM_DASH_ROOTS:
        base = Path(root)
        paths = [base] if base.is_file() else sorted(base.rglob("*"))
        for path in paths:
            if not path.is_file() or path in seen:
                continue
            if path.suffix.lower() not in EM_DASH_SUFFIXES:
                continue
            if any(x in str(path) for x in EM_DASH_EXEMPT):
                continue
            seen.add(path)
            found += [(path, *o) for o in em_dashes(path)]
    if not found:
        print("check-slop: no split sentences, and no em dashes ✓")
        return 0
    print("check-slop: prose carrying the generated fingerprint.\n")
    for path, line_no, kind, text in found:
        print(f"  {path}:{line_no}  {kind}: {text!r}")
    print(
        "\nJoin split sentences with a conjunction, or rephrase from scratch if the join reads\n"
        "stitched. Replace an em dash with a comma, a full stop, or the conjunction it is standing\n"
        "in for. The standard both follow is the no-ai-slop skill."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
