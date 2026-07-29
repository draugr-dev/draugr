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

# Enter the sandbox off-camera and warm Trivy's vulnerability database with a throwaway scan.
#
# The warm-up is not cosmetic. Trivy downloads its database on first use, and on a cold CI
# runner that download dominates the elapsed time — enough to fill the recording with a progress
# bar and run out of frames before the verdict prints. The GIF should show the product, not a
# one-time download, and every scan after a machine's first looks like this one.
Hide
Type "cd draugr-demo" Enter
Type "draugr scan . >/dev/null 2>&1" Enter
Wait@120s /\$ $/
Type "clear" Enter
Show

Type "draugr scan ." Sleep 600ms Enter

# Wait for the verdict rather than guessing at a duration. A fixed sleep is a bet on how fast the
# runner is that day, and losing that bet records a GIF of nothing. The regex matches the summary
# line the scan ends on.
Wait+Screen@120s /and \d+ more finding/
Sleep 4s  # hold on the verdict so it is readable before the GIF loops
