#!/usr/bin/env python3
"""Render a real scan as an SVG, for the README.

GitHub cannot show a terminal's colors. A fenced block there is passed through a syntax
highlighter that has no idea what it is looking at, so the bands, the severities and the version
that clears a finding all arrive in one shade of blue, and the one thing the output is for, telling
a reader what to look at first, is the thing that is lost.

So the README carries a picture of the terminal instead. The website keeps selectable text, where
`remark-terminal` gives it Draugr's own colors: a screenshot there would cost search, translation
and copy-and-paste to buy something that page already has.

An SVG rather than a PNG: text stays text, so it scales, stays small, and a reader can still select
it in a browser that opens the file directly. No browser is needed to produce it.

Reads ANSI on stdin and writes SVG to stdout. The argument is the command that produced it, drawn
as the prompt line above the output, because a picture of a result nobody can reproduce is a
picture of nothing:

    script -qec "draugr scan . --top 6" /dev/null |
      scripts/screenshot.py "draugr scan . --top 6" > docs/assets/scan.svg
"""
import html
import re
import sys

# The ground the terminal is drawn on, which is the product's own.
BG, FG = "#0b0e11", "#e6e8ea"
CELL_W, LINE_H, PAD = 8.05, 20.0, 18.0
FONT = ('"JetBrains Mono","SFMono-Regular",ui-monospace,"Menlo",'
        '"DejaVu Sans Mono",monospace')

SGR = re.compile(r"\x1b\[([0-9;]*)m")
OSC = re.compile(r"\x1b\]8;;([^\x07]*)\x07")
# Everything else a terminal writes to move the cursor about, which a picture has no use for.
OTHER = re.compile(r"\x1b\[[0-9;?]*[A-Za-ln-z]|\x1b[()][A-Z0-9]|\r")


def spans(line):
    """Split one line into (text, fg, bg, bold) runs."""
    out, fg, bg, bold, dim, pos = [], None, None, False, False, 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], fg, bg, bold, dim))
        pos = m.end()
        codes = [c for c in m.group(1).split(";") if c] or ["0"]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == "0":
                fg = bg = None
                bold = dim = False
            elif c == "1":
                bold = True
            elif c == "2":
                dim = True
            elif c == "7":
                fg, bg = bg or BG, fg or FG
            elif c == "38" and i + 1 < len(codes) and codes[i + 1] == "2":
                fg = "rgb(%s,%s,%s)" % tuple(codes[i + 2:i + 5])
                i += 4
            elif c == "48" and i + 1 < len(codes) and codes[i + 1] == "2":
                bg = "rgb(%s,%s,%s)" % tuple(codes[i + 2:i + 5])
                i += 4
            elif c in SIXTEEN:
                fg = SIXTEEN[c]
            i += 1
    if pos < len(line):
        out.append((line[pos:], fg, bg, bold, dim))
    return out


# The sixteen-color fallback, in the same hues the project uses, so a terminal that did not
# announce full color still produces a picture in the right palette.
SIXTEEN = {
    "30": "#0b0e11", "31": "#e5534b", "32": "#57ab5a", "33": "#e8b84b",
    "34": "#7ca6b8", "35": "#a371f7", "36": "#7ca6b8", "37": "#e6e8ea",
}


def main():
    raw = sys.stdin.read()
    # The report only. A progress bar redraws itself, and what it leaves behind is not what a
    # reader saw.
    if "\x1b[2K" in raw:
        raw = raw[raw.rindex("\x1b[2K") + 4:]
    lines = [OTHER.sub("", OSC.sub("", l)) for l in raw.rstrip("\n").split("\n")]
    if len(sys.argv) > 1:
        lines = [f"\x1b[38;2;232;184;75m$\x1b[0m {sys.argv[1]}", ""] + lines

    width = max((len(SGR.sub("", l)) for l in lines), default=0)
    w = PAD * 2 + width * CELL_W
    h = PAD * 2 + len(lines) * LINE_H

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" '
           f'viewBox="0 0 {w:.0f} {h:.0f}" font-family={html.escape(FONT, quote=True)!r} '
           f'font-size="13.5">',
           f'<rect width="100%" height="100%" rx="8" fill="{BG}"/>']
    for row, line in enumerate(lines):
        y = PAD + row * LINE_H + 14
        col = 0
        for text, fg, bg, bold, dim in spans(line):
            if not text:
                continue
            x = PAD + col * CELL_W
            if bg:
                out.append(f'<rect x="{x:.1f}" y="{y - 13:.1f}" width="{len(text) * CELL_W:.1f}" '
                           f'height="{LINE_H - 2:.1f}" rx="3" fill="{bg}"/>')
            if text.strip():
                color = fg or ("#78838d" if dim else FG)
                weight = ' font-weight="600"' if bold else ""
                out.append(f'<text x="{x:.1f}" y="{y:.1f}" fill="{color}"{weight} '
                           f'xml:space="preserve">{html.escape(text)}</text>')
            col += len(text)
    out.append("</svg>")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
