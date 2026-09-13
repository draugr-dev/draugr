#!/usr/bin/env python3
"""Fail when documentation a user reads names something only a contributor can look up.

The reader of `docs/` is running the tool, not building it. A Go package path, an exported symbol,
or one of the internal names for a subsystem tells them nothing they can act on and sends them
looking for a file that is not in front of them. Every instance found so far had the fact the
reader wanted already in the same sentence:

  No:  These are the shipped defaults (`pkg/prioritization/prioritization.go`).
  Yes: These are the shipped defaults.

  No:  Results render through a pluggable Reporter interface (`pkg/report`).
  Yes: Results render in any of these formats.

  No:  It replaces the binary you are running (`os.Executable()`).
  Yes: It replaces the binary you are running, so you are never left with an older copy.

  No:  a document written by an embedder calling `skald.RenderJSONFor` without it
  Yes: a document written without a gate at all

`Norn` and `Skald` are the code's names for the gate and the report. They are accurate, they appear
a hundred times in the source, and published writing says *the gate* and *the report*, because a
reader who meets `Skald` has no way to find out what it is.

This exists because the rule was enforced by memory while the rules around it had gates, and the
reviewer reading a diff does not catch it: the words look considered, because they were.

`docs/contributing/` is exempt. Its reader is the one person who does want the package name.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EXEMPT = {"contributing"}

# Fenced blocks come out first: a command that genuinely prints a package path, or an example in
# another language, is quoting something real rather than explaining Draugr to the reader.
FENCE = re.compile(r"^```.*?^```", re.S | re.M)
# A markdown link target may point into the tree. The catalog links every plugin to the doc kept
# beside its code, and that link is the only route a reader has to it.
LINK_TARGET = re.compile(r"\]\([^)]*\)")

CHECKS = (
    (
        "internal name for a subsystem",
        re.compile(r"\b(Norn|Skald)\b"),
        "published writing says the gate, the verdict, the report",
    ),
    (
        "Go source path",
        re.compile(r"`(?:pkg|internal|cmd)/[A-Za-z0-9_./-]+`"),
        "name what it does, not where it lives",
    ),
    (
        # The package half is required to be all lowercase, which is Go's own convention and what
        # separates `os.Executable` from the version placeholder `vX.Y.Z` that reads the same way
        # to a looser pattern.
        "Go symbol",
        re.compile(r"`[a-z][a-z0-9_]*\.[A-Z][A-Za-z0-9_]{2,}\(?\)?`"),
        "state the behavior; the call that implements it is not the reader's",
    ),
)


def offenders(text: str) -> list[tuple[int, str, str, str]]:
    """Line number, what was found, which rule, and what to do instead."""
    stripped = LINK_TARGET.sub("]()", FENCE.sub(lambda m: "\n" * m.group(0).count("\n"), text))
    out = []
    for lineno, line in enumerate(stripped.splitlines(), 1):
        for label, pattern, advice in CHECKS:
            for m in pattern.finditer(line):
                out.append((lineno, m.group(0), label, advice))
    return out


def main() -> int:
    if not DOCS.is_dir():
        print(f"check-docs-vocabulary: no docs at {DOCS}", file=sys.stderr)
        return 1

    found = 0
    for f in sorted(DOCS.rglob("*.md")):
        if set(f.relative_to(DOCS).parts) & EXEMPT:
            continue
        hits = offenders(f.read_text())
        if not hits:
            continue
        if not found:
            print("\n✗ Documentation naming something only a contributor can look up\n", file=sys.stderr)
        found += len(hits)
        rel = f.relative_to(ROOT)
        for lineno, text, label, advice in hits:
            print(f"  {rel}:{lineno}", file=sys.stderr)
            print(f"      {text}   ({label})", file=sys.stderr)
            print(f"      {advice}\n", file=sys.stderr)

    if found:
        print(f"  {found} to fix. docs/contributing/ is exempt; move it there if a "
              f"contributor is who needs it.\n", file=sys.stderr)
        return 1

    print("check-docs-vocabulary: docs name what a reader can act on ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
