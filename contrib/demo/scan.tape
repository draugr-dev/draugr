# vhs tape for the README demo image of zero-config `draugr scan .`.
# Render:  vhs contrib/demo/scan.tape   → contrib/demo/scan.png
#
# A still of the finished scan rather than a recording of it. The output is dense — a verdict,
# four priority bands, a control table and a ranked list — and an animation gives the reader a
# few seconds with it before looping back to an empty prompt, which is long enough to notice the
# colours and not long enough to read the rows. A still is read at the reader's pace, weighs a
# fraction as much on a page that has one job, and costs nothing to encode.
#
# It runs `draugr scan .` inside ./draugr-demo, so before rendering:
#   - `draugr` on PATH (a release build)
#   - scanners installed:  draugr tools install -y   (Trivy, Gitleaks) + Semgrep via pipx
#   - a findings-rich repo at ./draugr-demo — the sandbox is ideal:
#       git clone https://github.com/draugr-dev/draugr-demo draugr-demo
#     The directory name is the release name in the output, so it has to match the docs.
# The Demo screenshot workflow (.github/workflows/demo-screenshot.yml) does all of this and
# opens a PR with the regenerated image.
#
# There is deliberately no `Output`. vhs writes a recording only when asked for one, and a
# screenshot does not need the frames to be encoded — so the GIF pass, which is the slowest part
# of the render and the only reason ffmpeg is on the critical path, simply does not run.

Set Shell bash
Set FontSize 18
Set Width 1600
Set Height 1000
Set Theme "Dracula"
Set Padding 20

# The height has to fit the entire scan output. vhs renders a fixed viewport rather than a
# scrolling terminal, so anything past the bottom edge is never captured — including the summary
# line the Wait below matches on, which makes a height that is merely close fail as a timeout
# rather than as a cropped image. At font size 18 a row is about 22px, and the zero-config run
# currently prints 38 rows including the prompt. Leave headroom — the output grows as controls
# are added — but not so much that the image ends on a band of empty terminal.

# Enter the sandbox off-camera. The scanner databases are warmed by the workflow before vhs
# starts — Trivy downloads its database on first use, and on a cold runner that download
# dominates the elapsed time, enough to fill the terminal with a progress bar that is still on
# screen when the shot is taken. Warming it is setup, not something to show: doing it here meant
# detecting when a hidden command had finished, which is guesswork about a shell prompt rather
# than about Draugr.
Hide
Type "cd draugr-demo" Enter
# Clear before the capture. Hide stops the capture, not the terminal: without this the
# navigation the reader did not need to see is still on screen when Show brings it back.
Type "clear" Enter
Show

Type "draugr scan ." Sleep 600ms Enter

# Wait for the verdict rather than guessing at a duration. A fixed sleep is a bet on how fast the
# runner is that day, and losing that bet captures an empty terminal. The regex matches the
# summary line the scan ends on, so the still is taken when the output is complete rather than
# when a timer happened to elapse.
Wait+Screen@120s /and \d+ more finding/

Screenshot contrib/demo/scan.png

# vhs does not reliably flush a screenshot that is the last instruction in a tape
# (https://github.com/charmbracelet/vhs/issues/540), and it exits 0 either way — so without a
# command after it the render succeeds and produces nothing. The workflow checks that the file
# exists for the same reason: this is one upstream fix away from being unnecessary, and a step
# that quietly writes no image is exactly what a green tick should never mean.
Sleep 1s
