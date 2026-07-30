# vhs tape for the README demo GIF of zero-config `draugr scan .`.
# Render:  vhs contrib/demo/scan.tape   → contrib/demo/scan.gif
#
# It records `draugr scan .` inside ./draugr-demo, so before rendering:
#   - `draugr` on PATH (a release build)
#   - scanners installed:  draugr tools install -y   (Trivy, Gitleaks) + Semgrep via pipx
#   - a findings-rich repo at ./draugr-demo — the sandbox is ideal:
#       git clone https://github.com/draugr-dev/draugr-demo draugr-demo
#     The directory name is the release name in the output, so it has to match the docs.
# The Demo GIF workflow (.github/workflows/demo-gif.yml) does all of this and opens a PR
# with the regenerated GIF.

Output contrib/demo/scan.gif

Set Shell bash
Set FontSize 18
Set Width 1600
Set Height 820
Set Theme "Dracula"
Set Padding 20

# Enter the sandbox off-camera. The scanner databases are warmed by the workflow before vhs
# starts — Trivy downloads its database on first use, and on a cold runner that download
# dominates the elapsed time, enough to fill the recording with a progress bar and run out of
# frames before the verdict prints. Warming it is setup, not something to record: doing it here
# meant detecting when a hidden command had finished, which is guesswork about a shell prompt
# rather than about Draugr.
Hide
Type "cd draugr-demo" Enter
Show

Type "draugr scan ." Sleep 600ms Enter

# Wait for the verdict rather than guessing at a duration. A fixed sleep is a bet on how fast the
# runner is that day, and losing that bet records a GIF of nothing. The regex matches the summary
# line the scan ends on.
Wait+Screen@120s /and \d+ more finding/
Sleep 4s  # hold on the verdict so it is readable before the GIF loops
