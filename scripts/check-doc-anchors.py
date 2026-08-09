#!/usr/bin/env python3
"""Fail if a Markdown link points at a heading that does not exist.

A `[text](#some-heading)` that resolves to nothing renders as a normal link and jumps nowhere.
Nothing else notices: it is valid Markdown, the build does not read it, and the reader who
follows it is the first to find out — which makes it the kind of defect that accumulates
quietly in reference docs, where the cross-references are the navigation.

Renaming a heading is what breaks them, and renaming a heading is a routine edit. `## draugr
scan <saga.yaml>` becoming `## draugr scan [saga.yaml | dir]` invalidates every link to it, in
a diff where nothing looks like it touched a link — and most of those links are in other files,
so the change and the breakage are not even in the same part of the tree.

Cross-file links are checked too, and they are the reason this is worth running: the reference
pages are linked to from every guide and concept page, and it is the reference headings that
move. A missing *file* is left alone — that is a different class of problem, and a checker that
reports both at once tends to be run for neither.

`/docs` is republished from this repo, so a heading link that is dead here is dead on the
website, under a URL somebody may have bookmarked.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# GitHub's heading slug: lower-cased, punctuation dropped, whitespace to hyphens.
PUNCT = re.compile(r"[^\w\s-]")
SPACE = re.compile(r"\s")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.M)
# A link with a fragment: an optional path, then #anchor. Titles and absolute URLs are excluded
# by requiring the target to end at the closing paren.
LINK = re.compile(r"\]\(([^)\s#]*)#([^)\s]+)\)")
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
    files = tracked_markdown()
    # Every file's body and headings, read once: a reference page is linked to from a dozen others.
    bodies = {p: FENCE.sub("", (root / p).read_text(errors="replace")) for p in files}
    anchors = {p: {slug(m.group(2)) for m in HEADING.finditer(b)} for p, b in bodies.items()}

    broken: list[str] = []
    checked = 0
    for path, body in bodies.items():
        for m in LINK.finditer(body):
            target, anchor = m.group(1), m.group(2)
            if target:
                dest = Path(os.path.normpath(path.parent / target))
                # A link to a file this check does not hold is somebody else's problem: an
                # untracked path, or one that does not exist at all.
                if dest not in anchors:
                    continue
                where = f"{dest}#{anchor}"
            else:
                dest, where = path, f"#{anchor}"
            checked += 1
            if anchor not in anchors[dest]:
                line = body[: m.start()].count("\n") + 1
                broken.append(f"{path}:{line}: {where} matches no heading in {dest}")

    if broken:
        print("✗ Markdown links to headings that do not exist", file=sys.stderr)
        for b in broken:
            print(f"  {b}", file=sys.stderr)
        return 1
    print(f"check-doc-anchors: {checked} heading link(s) resolve ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
