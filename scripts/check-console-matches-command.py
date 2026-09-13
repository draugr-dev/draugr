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
  FIX FIRST  top N of M        the table was capped      → --top N
  EVIDENCE                     the evidence block ran    → --evidence

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
TOP = re.compile(r"^(?:FIX FIRST|CHANGED)\s+top (\d+) of \d+", re.M)
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
    if top and f"--top {top.group(1)}" not in cmd:
        out.append(f"the block shows a table capped at {top.group(1)} and the command does not ask for it")

    if re.search(r"^EVIDENCE\s*$", block, re.M) and "--evidence" not in cmd:
        out.append("the block carries the evidence section and the command does not ask for it")
    return out


def main() -> int:
    files = sorted(ROOT.glob("docs/**/*.md")) + [ROOT / "README.md"]
    checked, bad = 0, 0
    for path in files:
        if not path.exists():
            continue
        for cmd, block in commands_and_blocks(path.read_text()):
            checked += 1
            for problem in problems(cmd, block):
                bad += 1
                rel = path.relative_to(ROOT)
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
    sys.exit(main())
