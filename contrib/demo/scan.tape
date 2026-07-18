# vhs tape for the README demo GIF of zero-config `draugr scan .`.
# Render:  vhs contrib/demo/scan.tape   → contrib/demo/scan.gif
#
# It records `draugr scan .` inside ./demo, so before rendering:
#   - `draugr` on PATH (a release build)
#   - scanners installed:  draugr tools install -y   (Trivy, Gitleaks) + Semgrep via pipx
#   - a findings-rich repo at ./demo — the sandbox is ideal:
#       git clone https://github.com/draugr-dev/draugr-demo demo
# The Demo GIF workflow (.github/workflows/demo-gif.yml) does all of this and opens a PR
# with the regenerated GIF.

Output contrib/demo/scan.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set Padding 20

# Enter the sandbox off-camera, then record the money shot.
Hide
Type "cd demo" Enter
Show
Type "draugr scan ." Sleep 600ms Enter
Sleep 12s
