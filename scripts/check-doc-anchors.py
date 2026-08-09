#!/usr/bin/env python3
"""Fail if a Markdown link points at a heading in the same file that does not exist.

A `[text](#some-heading)` that resolves to nothing renders as a normal link and jumps nowhere.
Nothing else notices: it is valid Markdown, the build does not read it, and the reader who
follows it is the first to find out — which makes it the kind of defect that accumulates
quietly in reference docs, where the cross-references are the navigation.

Renaming a heading is what breaks them, and renaming a heading is a routine edit. `## draugr
scan <saga.yaml>` becoming `## draugr scan [saga.yaml | dir]` silently invalidates every link
to it, in a diff where nothing about the change looks like it touched a link.

Only same-file anchors are checked. A cross-file link is a different problem needing a
different fix, and a checker that reports both at once tends to be run for neither.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# GitHub's heading slug: lower-cased, punctuation dropped, whitespace to hyphens.
PUNCT = re.compile(r"[^\w\s-]")
SPACE = re.compile(r"\s")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.M)
LINK = re.compile(r"\]\(#([^)]+)\)")
# A fenced block holds examples, not headings — a `# comment` in bash is not a heading.
FENCE = re.compile(r"^```.*?^```", re.M | re.S)


def slug(heading: str) -> str:
    return SPACE.sub("-", PUNCT.sub("", heading.strip().lower()))


def tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md"], capture_output=True, text=True, check=True
    ).stdout
    return [Path(p) for p in out.split("\0") if p]


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    broken: list[str] = []
    for path in tracked_markdown():
        text = (root / path).read_text(errors="replace")
        body = FENCE.sub("", text)
        anchors = {slug(m.group(2)) for m in HEADING.finditer(body)}
        for m in LINK.finditer(body):
            if m.group(1) not in anchors:
                line = body[: m.start()].count("\n") + 1
                broken.append(f"{path}:{line}: #{m.group(1)} matches no heading in this file")

    if broken:
        print("✗ Markdown links to headings that do not exist", file=sys.stderr)
        for b in broken:
            print(f"  {b}", file=sys.stderr)
        return 1
    print("check-doc-anchors: every same-file heading link resolves ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
