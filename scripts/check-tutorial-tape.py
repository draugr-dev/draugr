#!/usr/bin/env python3
"""Fail if the recording's tape and the tutorial disagree on what is typed.

docs/getting-started/tutorial.tape is the tutorial recorded: VHS types each command and runs it.
The tape is a second copy of the page's commands, and a re-pin edits the page, so a tape left
behind records the old release or the old demo commit while every check of the page passes.
Nothing on the page shows the difference, and the recording looks right until someone compares
the version on screen with the one on the page.

So the commands the tape types on camera must be the commands the page shows, in the page's
order, character for character after joining a line the page continues with a backslash. A
command only the tape runs, such as a closing look at the scanners' data, is allowed when the
comment line before it starts `# Not on the page:`. Lines typed between Hide and Show set up the
recording and are not compared.

Usage: scripts/check-tutorial-tape.py [tutorial.md tutorial.tape]
"""
import re
import sys

PAGE = "docs/getting-started/tutorial.md"
TAPE = "docs/getting-started/tutorial.tape"
EXEMPT = "# Not on the page:"


def page_commands(text):
    """Every command in a console block (lines after `$ `) and every line of a bash block."""
    out, fence, pending = [], None, ""
    for line in text.split("\n"):
        if line.startswith("```"):
            fence = None if fence else (line[3:].strip() or "text")
            continue
        if fence not in ("console", "bash"):
            continue
        if pending:
            pending += " " + line.strip()
        elif fence == "console" and line.startswith("$ "):
            pending = line[2:]
        elif fence == "bash" and line.strip() and not line.lstrip().startswith("#"):
            pending = line.strip()
        else:
            continue
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        out.append(" ".join(pending.split()))
        pending = ""
    return out


TYPE = re.compile(r'^Type(?:@\S+)?\s+(?:"(.*)"|`(.*)`)\s*$')


def tape_commands(text):
    """The commands typed on camera, without stage titles, clears and exempt lines."""
    out, hidden, exempt = [], False, False
    for line in text.split("\n"):
        s = line.strip()
        if s == "Hide":
            hidden = True
        elif s == "Show":
            hidden = False
        elif s.startswith(EXEMPT):
            exempt = True
        m = TYPE.match(s)
        if not m or hidden:
            continue
        typed = m.group(1) if m.group(1) is not None else m.group(2)
        if typed.startswith("# ") or typed == "clear":
            continue
        if exempt:
            exempt = False
            continue
        out.append(" ".join(typed.split()))
    return out


def main(argv):
    page_path, tape_path = (argv[1], argv[2]) if len(argv) == 3 else (PAGE, TAPE)
    try:
        page = page_commands(open(page_path, encoding="utf-8").read())
        tape = tape_commands(open(tape_path, encoding="utf-8").read())
    except OSError as err:
        print(f"check-tutorial-tape: {err}", file=sys.stderr)
        return 1
    if not page or not tape:
        print(f"check-tutorial-tape: no commands read from {page_path if not page else tape_path}",
              file=sys.stderr)
        return 1
    for i in range(max(len(page), len(tape))):
        want = page[i] if i < len(page) else "(nothing: the page has no more commands)"
        got = tape[i] if i < len(tape) else "(nothing: the tape has no more commands)"
        if want != got:
            print(f"{tape_path} types command {i + 1} differently from {page_path}:\n"
                  f"  page: {want}\n  tape: {got}\n"
                  f"Make the tape type what the page shows, or mark a tape-only command with a "
                  f"comment line starting {EXEMPT!r}.", file=sys.stderr)
            return 1
    print(f"tutorial-tape: the tape types the page's {len(page)} commands in order")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
