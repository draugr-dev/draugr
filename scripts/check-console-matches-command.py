#!/usr/bin/env python3
"""Fail when a pasted console block could not have come from the command above it.

Documentation quotes a command and then the output it produces. The two are written minutes apart
and read as one thing, so a block pasted from a slightly different run is invisible: the prose is
right, the output is real output, and the only wrong part is that it is the output of something
else. A reader who copies the command gets a different answer from the one the page just showed
them, on a page whose whole premise is that the output can be trusted.

This does not run anything. It compares what the block *claims about its own run* against the flags
in the command, which is enough to catch the mismatch that actually occurs:

  draugr scan draugr.saga.yaml --labels team=web
  →  DRAUGR  FAIL  demo 1.0  (scope: 1 of 3 components; sca)

The block says a control filter was applied. The command has none, so the paste came from a run
with `--controls sca` and the reader will not reproduce it.

Four claims are checkable, all of them rendered by the scan report from what it was asked for:

  (scope: N of M components)   a component was narrowed  → --components/--labels/--exposure/--criticality
  (scope: …; sca, secrets)     a control was narrowed    → --controls
  FIX FIRST  top N of M        the table was capped      → --top N, unless N is the default
  EVIDENCE                     the evidence block ran    → --evidence

`--top` has a **different default per subcommand**, 10 for `scan` and 0 for `diff`, so a capped
table is evidence of a flag only when the cap is not the one that subcommand would have produced
anyway. Reading `top 10` after a bare `draugr scan` as a mismatch fails the most ordinary paste
there is, and a check that fails correct pages is one somebody switches off.

Everything else about a block is beyond a static check. `make examples` regenerates output from a
real run and is what keeps the rest honest.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A fenced block, with its language, so a command and its output can be paired in order.
FENCE = re.compile(r"```(\w*)\n(.*?)```", re.S)
# What only this renderer prints, so a console fence carrying one is a run rather than a shell session.
CONSOLE_SHAPES = ("DRAUGR ", "FIX FIRST", "WHAT TO DO", "CONTROLS\n", "COMPONENTS\n", "EVIDENCE\n")
SCOPE = re.compile(r"\(scope: ([^)]*)\)")
TOP = re.compile(r"^(FIX FIRST|CHANGED)\s+top (\d+) of \d+", re.M)
# What each subcommand caps at when nobody asks. The heading names which one rendered the block,
# which is a surer signal than the command, since the pairing takes whichever command came last.
DEFAULT_TOP = {"FIX FIRST": 10, "CHANGED": 0}
# Narrowing a run to part of the components, by name or by what they are.
COMPONENT_FLAGS = ("--components", "--labels", "--exposure", "--criticality")


def commands_and_blocks(text: str):
    """Yield (command, console_block) in document order, pairing each block with the command above it."""
    pending = None
    for m in FENCE.finditer(text):
        lang, body = m.group(1), m.group(2)
        if lang in ("bash", "sh", "console") and re.search(r"\bdraugr (scan|diff)\b", body):
            lines = [ln.strip() for ln in body.splitlines() if re.search(r"\bdraugr (scan|diff)\b", ln)]
            if lines:
                pending = lines[-1]
        if lang == "console" and any(s in body for s in CONSOLE_SHAPES):
            if pending:
                yield pending, body
    return


def problems(cmd: str, block: str) -> list[str]:
    out = []
    scope = SCOPE.search(block)
    if scope:
        parts = [p.strip() for p in scope.group(1).split(";")]
        narrowed_components = any("components" in p for p in parts)
        narrowed_controls = [p for p in parts if "components" not in p]
        if narrowed_components and not any(f in cmd for f in COMPONENT_FLAGS):
            out.append(
                "the block says the components were narrowed and the command narrows none "
                f"(expected one of {', '.join(COMPONENT_FLAGS)})"
            )
        if narrowed_controls and "--controls" not in cmd:
            out.append(
                f"the block says only {narrowed_controls[0]!r} ran and the command has no --controls"
            )
        if not narrowed_controls and "--controls" in cmd:
            out.append("the command narrows the controls and the block's scope does not say so")
    elif "--controls" in cmd or any(f in cmd for f in COMPONENT_FLAGS):
        out.append("the command narrows the run and the block claims no scope")

    top = TOP.search(block)
    if top:
        shown = int(top.group(2))
        default = DEFAULT_TOP[top.group(1)]
        if shown != default and f"--top {shown}" not in cmd:
            out.append(
                f"the block shows a table capped at {shown} and the command does not ask for it "
                f"({top.group(1)} caps at {default} on its own)"
            )

    if re.search(r"^EVIDENCE\s*$", block, re.M) and "--evidence" not in cmd:
        out.append("the block carries the evidence section and the command does not ask for it")
    return out


def markdown_under(roots: list[str]) -> list[Path]:
    """Every .md under each root, or the roots themselves where one names a file."""
    out: list[Path] = []
    for root in roots:
        path = Path(root)
        out.extend(sorted(path.rglob("*.md")) if path.is_dir() else [path])
    return out


def main(argv: list[str]) -> int:
    # Paths make this usable on a corpus that is not this repository. The website quotes the same
    # console output and lives somewhere this repo's CI cannot reach, so it runs the script from
    # its own build rather than keeping a second copy of these rules in step with this one.
    files = markdown_under(argv) if argv else sorted(ROOT.glob("docs/**/*.md")) + [ROOT / "README.md"]
    checked, bad = 0, 0
    for path in files:
        if not path.exists():
            continue
        for cmd, block in commands_and_blocks(path.read_text()):
            checked += 1
            for problem in problems(cmd, block):
                bad += 1
                rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
                print(f"{rel}: {problem}")
                print(f"    command: {cmd}")
    if bad:
        print()
        print("A pasted block has to be the output of the command printed above it. Re-run the")
        print("command as written and paste what it says, or correct the command to the one that")
        print("produced the block. `make examples` prints real output from the demo sandbox.")
        return 1
    print(f"check-console-matches-command: {checked} pasted run(s) match the command above them ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
